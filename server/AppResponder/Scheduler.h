#ifndef _SCHEDULER_H_
#define _SCHEDULER_H_

#include <list>
#include <vector>
#include <map>
#include <string>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <random>
#include "fifo_def.h"
#include "../Include/datatypes.h"

enum SchedulerType {
    SCHED_FCFS,
    SCHED_DPF,
    SCHED_DPACK,
    SCHED_EXPIRELA
};

struct Task {
    FIFO_MSG* msg;
    std::chrono::steady_clock::time_point arrival_time;
    uint32_t request_budget;
    uint32_t session_id;
    uint32_t data_num;
    std::vector<uint32_t> data_ids; // Store requested data IDs
    bool is_schedulable; // Only SHIELD_REQ with proposal data is schedulable
};

class Scheduler {
public:
    Scheduler();
    ~Scheduler();

    void push(FIFO_MSG* msg);
    FIFO_MSG* pop();
    void close();

private:
    SchedulerType algorithm;
    std::list<Task> queue;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    bool m_closed;

    // Data Block Budgets
    std::map<uint32_t, uint32_t> block_budgets;
    std::default_random_engine generator;
    std::normal_distribution<double> distribution;
    uint32_t max_observed_budget;

    uint32_t get_remaining_budget(uint32_t data_id);
    void deduct_budget(const Task& task);
    bool check_budget(const Task& task);

    // ExpireLA weights
    double w1 = 3.0; // Fairness
    double w2 = 2.0; // Efficiency
    double w3 = 1.5; // QoS

    Task select_task_fcfs();
    Task select_task_dpf();
    Task select_task_dpack();
    Task select_task_expirela();

    void parse_task(Task& task);
};

#endif
