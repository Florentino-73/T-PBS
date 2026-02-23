#include "Scheduler.h"
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <glog/logging.h>

Scheduler::Scheduler() : m_closed(false), max_observed_budget(2000000), distribution(8.0, 2.0) {
    const char* algo_env = getenv("SCHEDULER_TYPE");
    if (algo_env) {
        std::string algo(algo_env);
        if (algo == "fcfs") algorithm = SCHED_FCFS;
        else if (algo == "dpf" || algo == "dpf_t" || algo == "dpf_n") algorithm = SCHED_DPF;
        else if (algo == "dpack") algorithm = SCHED_DPACK;
        else if (algo == "expirela") algorithm = SCHED_EXPIRELA;
        else algorithm = SCHED_FCFS;
    } else {
        algorithm = SCHED_FCFS;
    }
    LOG(INFO) << "Scheduler initialized with algorithm: " << algorithm;
}

Scheduler::~Scheduler() {
    close();
}

void Scheduler::close() {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_closed = true;
    m_cond.notify_all();
}

void Scheduler::push(FIFO_MSG* msg) {
    std::unique_lock<std::mutex> lock(m_mutex);
    Task task;
    task.msg = msg;
    task.arrival_time = std::chrono::steady_clock::now();
    parse_task(task);
    queue.push_back(task);
    m_cond.notify_one();
}

void Scheduler::parse_task(Task& task) {
    task.is_schedulable = false;
    task.request_budget = 0;
    task.data_num = 0;
    task.session_id = 0;
    task.data_ids.clear();

    if (task.msg->header.type == FIFO_SHIELD_REQ) {
        SHIELD_REQ_MSG* shield_req = (SHIELD_REQ_MSG*)task.msg->msgbuf;
        // Check if it is a batch request (type 2 or 3)
        if (shield_req->type == 2 || shield_req->type == 3) {
            proposal_data_batch* proposal = (proposal_data_batch*)shield_req->buf;
            task.request_budget = proposal->request_budget;
            task.data_num = proposal->data_num;
            task.session_id = shield_req->session_id; // Use session_id from shield header
            task.is_schedulable = true;

            // Extract data IDs
            // buf contains data_num * uint32_t IDs
            uint32_t* ids = (uint32_t*)proposal->buf;
            for (uint32_t i = 0; i < task.data_num; ++i) {
                task.data_ids.push_back(ids[i]);
            }
            
            if (task.request_budget > max_observed_budget) {
                max_observed_budget = task.request_budget;
            }
        }
    }
}

uint32_t Scheduler::get_remaining_budget(uint32_t data_id) {
    if (block_budgets.find(data_id) == block_budgets.end()) {
        // Initialize with Gaussian distribution (mean 8, stddev 2) scaled to 1,000,000
        double val = distribution(generator);
        if (val < 1.0) val = 1.0; // Minimum budget
        block_budgets[data_id] = (uint32_t)(val * 1000000);
    }
    return block_budgets[data_id];
}

bool Scheduler::check_budget(const Task& task) {
    if (!task.is_schedulable) return true; // Non-schedulable tasks (e.g. handshake) don't consume budget

    for (uint32_t id : task.data_ids) {
        if (get_remaining_budget(id) < task.request_budget) {
            return false;
        }
    }
    return true;
}

void Scheduler::deduct_budget(const Task& task) {
    if (!task.is_schedulable) return;

    for (uint32_t id : task.data_ids) {
        uint32_t current = get_remaining_budget(id);
        if (current >= task.request_budget) {
            block_budgets[id] = current - task.request_budget;
        } else {
            block_budgets[id] = 0;
        }
    }
}

FIFO_MSG* Scheduler::pop() {
    std::unique_lock<std::mutex> lock(m_mutex);
    while (queue.empty() && !m_closed) {
        m_cond.wait(lock);
    }

    if (m_closed && queue.empty()) {
        return NULL;
    }

    Task selected_task;
    bool found = false;

    // If algorithm is FCFS, we process head. If head fails budget, we reject it and try next.
    if (algorithm == SCHED_FCFS) {
        while (!queue.empty()) {
            Task& t = queue.front();
            if (check_budget(t)) {
                selected_task = t;
                queue.pop_front();
                found = true;
                break;
            } else {
                // Reject: Remove from queue and free message
                LOG(INFO) << "FCFS: Rejecting task due to insufficient budget. Session: " << t.session_id;
                free(t.msg);
                queue.pop_front();
                // Continue to next task
            }
        }
    } else {
        // For other algorithms, we scan the queue for the best task that satisfies budget.
        // We merge the cleanup and selection pass to optimize performance.
        
        if (queue.empty()) return NULL;

        switch (algorithm) {
            case SCHED_DPF: selected_task = select_task_dpf(); break;
            case SCHED_DPACK: selected_task = select_task_dpack(); break;
            case SCHED_EXPIRELA: selected_task = select_task_expirela(); break;
            default: selected_task = select_task_fcfs(); break;
        }
        
        if (selected_task.msg != NULL) {
            found = true;
        }
    }

    if (found) {
        deduct_budget(selected_task);
        return selected_task.msg;
    }

    return NULL;
}

Task Scheduler::select_task_fcfs() {
    // Should be called only when queue is not empty and head is valid
    Task t = queue.front();
    queue.pop_front();
    return t;
}

Task Scheduler::select_task_dpf() {
    // DPF: Max-Min Fairness based on Dominant Share
    // FE_i = max(L_{i,j} / c_j)
    // Select task with MINIMUM FE_i
    
    auto best_it = queue.end();
    double min_fe = 1e9; // Infinity

    for (auto it = queue.begin(); it != queue.end(); ) {
        if (!check_budget(*it)) {
            LOG(INFO) << "Rejecting task due to insufficient budget. Session: " << it->session_id;
            free(it->msg);
            it = queue.erase(it);
            continue;
        }

        if (!it->is_schedulable) {
            // Prioritize non-schedulable tasks (e.g. handshake)
            best_it = it;
            break;
        }

        double max_share = 0.0;
        for (uint32_t id : it->data_ids) {
            double c_j = (double)get_remaining_budget(id);
            if (c_j <= 0) c_j = 0.1; // Should not happen if check_budget passed
            double share = (double)it->request_budget / c_j;
            if (share > max_share) max_share = share;
        }

        if (max_share < min_fe) {
            min_fe = max_share;
            best_it = it;
        }
        ++it;
    }

    if (best_it != queue.end()) {
        Task t = *best_it;
        queue.erase(best_it);
        return t;
    }
    
    Task empty;
    empty.msg = NULL;
    return empty;
}

Task Scheduler::select_task_dpack() {
    // Dpack: Efficiency Oriented
    // Efficiency = Value / Cost. Assume Value = 1 (or data_num).
    // Prioritize MINIMUM total consumption (or max efficiency).
    // Here: Efficiency = 1 / request_budget (since data_num is constant 10 usually)
    // So we want MINIMUM request_budget.
    
    auto best_it = queue.end();
    uint32_t min_cost = 0xFFFFFFFF;

    for (auto it = queue.begin(); it != queue.end(); ) {
        if (!check_budget(*it)) {
            LOG(INFO) << "Rejecting task due to insufficient budget. Session: " << it->session_id;
            free(it->msg);
            it = queue.erase(it);
            continue;
        }

        if (!it->is_schedulable) {
            best_it = it;
            break;
        }

        if (it->request_budget < min_cost) {
            min_cost = it->request_budget;
            best_it = it;
        }
        ++it;
    }

    if (best_it != queue.end()) {
        Task t = *best_it;
        queue.erase(best_it);
        return t;
    }
    
    Task empty;
    empty.msg = NULL;
    return empty;
}

Task Scheduler::select_task_expirela() {
    // ExpireLA: E = w1 * FE + w2 * EE + w3 * QoS
    // We want to MAXIMIZE E.
    
    auto best_it = queue.end();
    double max_score = -1.0;
    
    auto now = std::chrono::steady_clock::now();

    for (auto it = queue.begin(); it != queue.end(); ) {
        if (!check_budget(*it)) {
            LOG(INFO) << "Rejecting task due to insufficient budget. Session: " << it->session_id;
            free(it->msg);
            it = queue.erase(it);
            continue;
        }

        if (!it->is_schedulable) {
            best_it = it;
            break;
        }

        // 1. Fairness (FE): 
        // DPF minimizes Dominant Share (max_share).
        // To prioritize "fair" tasks (low share), we invert it.
        // FE_score = 1 - max_share. (Assuming max_share <= 1, which is true if budget check passed)
        double max_share = 0.0;
        for (uint32_t id : it->data_ids) {
            double c_j = (double)get_remaining_budget(id);
            if (c_j <= 0) c_j = 0.1;
            double share = (double)it->request_budget / c_j;
            if (share > max_share) max_share = share;
        }
        double fe_score = 1.0 - max_share;
        if (fe_score < 0) fe_score = 0;

        // 2. Efficiency (EE): 
        // Dpack minimizes cost.
        // EE_score = 1 - (cost / max_possible_cost).
        // Use max_observed_budget for normalization.
        double ee_score = 1.0 - ((double)it->request_budget / (double)max_observed_budget);
        if (ee_score < 0) ee_score = 0;

        // 3. QoS: Waiting time
        double waiting_ms = (double)std::chrono::duration_cast<std::chrono::milliseconds>(now - it->arrival_time).count();
        double qos_score = waiting_ms / 10000.0; // 10 seconds waiting = score 1
        if (qos_score > 1.0) qos_score = 1.0; // Cap at 1

        double score = w1 * fe_score + w2 * ee_score + w3 * qos_score;

        if (score > max_score) {
            max_score = score;
            best_it = it;
        }
        ++it;
    }

    if (best_it != queue.end()) {
        Task t = *best_it;
        queue.erase(best_it);
        return t;
    }
    
    Task empty;
    empty.msg = NULL;
    return empty;
}
