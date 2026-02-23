#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <map>
#include <sys/stat.h>
#include <sched.h>

#include "EnclaveResponder_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include <sgx_uswitchless.h>

#include "cpdef.h"
#include "fifo_def.h"
#include "../Include/datatypes.h"

#include "CPTask.h"
#include "CPServer.h"
#include "config.h"

sgx_enclave_id_t e2_enclave_id = 0;

#define ENCLAVE_RESPONDER_NAME "libenclave_responder.signed.so"

Arg arg;
static hashtable *ht = NULL;
static MACbuffer *MACbuf = NULL;

CPTask::CPTask(int _pageSize, int _numThreads, int _managerCap){
    pageSize = _pageSize;
    numThreads = _numThreads;
    managerCap = _managerCap;
    arg.port_num = get_server_port(); // Initialize port from config
}

/**
 * init default configuration values
 **/
void configuration_init(int pageSize, int numThreads, int managerCap)
{
    arg.port_num = get_server_port();
    arg.max_buf_size = 256;
    arg.num_threads = numThreads;          // cur_max thread: 12
    arg.bucket_size = 8 * 16 * 16; // mac num is: 30*bucket_size;
    arg.tree_root_size = 4 * 16 * 16;
    arg.page_size = pageSize;
    arg.manager_cap = managerCap;

    /** Optimization **/
    arg.key_opt = false;
    arg.mac_opt = false;
}

/**
 * For mac bucketing optimization
 * create mac buffer
 **/
MACbuffer *macbuffer_create(int size)
{
    MACbuffer *Mbuf = NULL;

    Mbuf = (MACbuffer *)malloc(sizeof(MACbuffer));
    Mbuf->entry = (MACentry *)malloc(sizeof(MACentry) * size);
    for (int i = 0; i < size; i++)
    {
        Mbuf->entry[i].size = 0;
    }
    return Mbuf;
}

/**
 * create new hashtable
 **/
hashtable *ht_create(int size)
{
    hashtable *ht = NULL;

    if (size < 1)
        return NULL;

    /* Allocate the table itself. */
    if ((ht = (hashtable *)malloc(sizeof(hashtable))) == NULL)
        return NULL;

    /* Allocate pointers to the head nodes. */
    if ((ht->table = (page_entry **)malloc(sizeof(page_entry *) * size)) == NULL)
        return NULL;

    for (int i = 0; i < size; i++)
        ht->table[i] = NULL;

    ht->size = size;

    return ht;
}

/**
 * creating server threads working inside the enclave
 **/
void *load_and_initialize_threads(void *temp)
{
    ecall_worker_thread(e2_enclave_id, (hashtable *)ht, (MACbuffer *)MACbuf);
}

/* Function Description: load responder enclave
 * */
int load_enclaves()
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int update = 0;

    // For release-signed enclaves, use debug_flag=0
    // For debug-signed enclaves, use debug_flag=1
    int debug_flag = SGX_DEBUG_FLAG;
    ret = sgx_create_enclave(ENCLAVE_RESPONDER_NAME, debug_flag, &token, &update, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        LOG(ERROR) << "failed to load enclave " << ENCLAVE_RESPONDER_NAME << ", error code is 0x" << std::hex << ret;
        return -1;
    }

    return 0;
}

int initialize_enclave(const sgx_uswitchless_config_t *us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    const void *enclave_ex_p[32] = {0};

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void *)us_config;
    ret = sgx_create_enclave_ex(ENCLAVE_RESPONDER_NAME, 1, NULL, NULL, &e2_enclave_id, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS)
    {
        printf("SWITCHLESS ENCLAVE LOAD FAILED.. ERROR CODE : 0X%x \n", ret);
        return -1;
    }

    return 0;
}

/* Function Description:
 *  This function responds to initiator enclave's connection request by generating and sending back ECDH message 1
 * Parameter Description:
 *  [input] clientfd: this is client's connection id. After generating ECDH message 1, server would send back response through this connection id.
 * */
int generate_and_send_session_msg1_resp(int clientfd)
{
    int retcode = 0;
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    SESSION_MSG1_RESP msg1resp;
    FIFO_MSG *fifo_resp = NULL;
    size_t respmsgsize;

    memset(&msg1resp, 0, sizeof(SESSION_MSG1_RESP));

    LOG(INFO) << "Calling session_request ECALL...";
    // call responder enclave to generate ECDH message 1
    ret = session_request(e2_enclave_id, &status, &msg1resp.dh_msg1, &msg1resp.sessionid);
    if (ret != SGX_SUCCESS || status != 0)
    {
        LOG(ERROR) << "failed to do ECALL session_request. error code is 0x" << std::hex << ret << ", status: 0x" << status;
        return -1;
    }
    LOG(INFO) << "session_request ECALL success. Session ID: " << msg1resp.sessionid;

    respmsgsize = sizeof(FIFO_MSG) + sizeof(SESSION_MSG1_RESP);
    fifo_resp = (FIFO_MSG *)malloc(respmsgsize);
    if (!fifo_resp)
    {
        printf("memory allocation failure.\n");
        return -1;
    }
    memset(fifo_resp, 0, respmsgsize);

    fifo_resp->header.type = FIFO_DH_RESP_MSG1;
    fifo_resp->header.size = sizeof(SESSION_MSG1_RESP);

    memcpy(fifo_resp->msgbuf, &msg1resp, sizeof(SESSION_MSG1_RESP));

    // send message 1 to client
    if (send(clientfd, reinterpret_cast<char *>(fifo_resp), static_cast<int>(respmsgsize), 0) == -1)
    {
        LOG(ERROR) << "fail to send msg1 response.";
        retcode = -1;
    }
    free(fifo_resp);
    return retcode;
}

/* Function Description:
 *  This function process ECDH message 2 received from client and send message 3 to client
 * Parameter Description:
 *  [input] clientfd: this is client's connection id
 *  [input] msg2: this contains ECDH message 2 received from client
 * */
int process_exchange_report(int clientfd, SESSION_MSG2 *msg2)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG *response;
    SESSION_MSG3 *msg3;
    size_t msgsize;

    if (!msg2)
        return -1;

    msgsize = sizeof(FIFO_MSG_HEADER) + sizeof(SESSION_MSG3);
    response = (FIFO_MSG *)malloc(msgsize);
    if (!response)
    {
        printf("memory allocation failure\n");
        return -1;
    }
    memset(response, 0, msgsize);

    response->header.type = FIFO_DH_MSG3;
    response->header.size = sizeof(SESSION_MSG3);

    msg3 = (SESSION_MSG3 *)response->msgbuf;
    msg3->sessionid = msg2->sessionid;

    // call responder enclave to process ECDH message 2 and generate message 3
    ret = exchange_report(e2_enclave_id, &status, &msg2->dh_msg2, &msg3->dh_msg3, msg2->sessionid);
    if (ret != SGX_SUCCESS)
    {
        printf("EnclaveResponse_exchange_report failure.\n");
        free(response);
        return -1;
    }

    // send ECDH message 3 to client
    if (send(clientfd, reinterpret_cast<char *>(response), static_cast<int>(msgsize), 0) == -1)
    {
        printf("server_send() failure.\n");
        free(response);
        return -1;
    }

    free(response);

    return 0;
}

/* Function Description: This is process session close request from client
 * Parameter Description:
 *  [input] clientfd: this is client connection id
 *  [input] close_req: this is pointer to client's session close request
 * */
int process_close_req(int clientfd, SESSION_CLOSE_REQ *close_req)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG close_ack;

    if (!close_req)
        return -1;

    // call responder enclave to close this session
    ret = end_session(e2_enclave_id, &status, close_req->session_id);
    if (ret != SGX_SUCCESS)
        return -1;

    // send back response
    close_ack.header.type = FIFO_DH_CLOSE_RESP;
    close_ack.header.size = 0;

    if (send(clientfd, reinterpret_cast<char *>(&close_ack), sizeof(FIFO_MSG), 0) == -1)
    {
        printf("server_send() failure.\n");
        return -1;
    }

    return 0;
}

void set_affinity(sgx_uswitchless_worker_type_t type, sgx_uswitchless_worker_event_t event, const sgx_uswitchless_worker_stats_t *stats)
{
    // type: worker type : SGX_USWITCHLESS_WORKER_tYPE_UNTRUSTED, SGX_USWITCHLESS_WORKER_TYPE_TRUSED.
    // event:  type of the event occured; SGX_USWITCHLESS_WORKER_EVENT_ (START, IDLE, MISS, EXIT, NUM)
    // stats: pointer to statistic data. {UINT64_T PROCESSED, UINT64_T MISSED};
    static int cpu_idx = 0;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    CPU_SET(cpu_idx % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    cpu_idx += 1;

    // set affinity
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0)
    {
        printf("set affinity failed..\n");
    }
}

void CPTask::run()
{
    // ecall: msg_pass;
    LOG(INFO) << "CPTask, start run.";
    FIFO_MSG *message = NULL;
    sgx_launch_token_t token = {0};
    sgx_status_t status;

    /* Shield variables */
    pthread_t *threads;
    uint32_t switchless = 0; // Disable switchless for debugging

    if (switchless)
    {
        /* SGX INIT */
        LOG(INFO)<<"SWITHLESS LOAD ENCLAVE";
        sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
        us_config.num_uworkers = 2;
        us_config.num_tworkers = 2;
        us_config.callback_func[0] = set_affinity;
        if (initialize_enclave(&us_config) != 0) {
            LOG(WARNING)<<"SWITCHLESS failed, fallback to ORIGINAL LOAD ENCLAVE";
            load_enclaves();
        }
    }
    else
    {
        // Already loaded in main(), skip
    }

    /* Shield Store initiation */
    configuration_init(pageSize, numThreads, managerCap);
    ht = ht_create(arg.bucket_size);
    MACbuf = macbuffer_create(arg.bucket_size);
    ecall_enclave_init_values(e2_enclave_id, ht, MACbuf, arg);

    /* Shield thread creation */
    threads = (pthread_t *)malloc(sizeof(pthread_t) * (arg.num_threads));
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_set_t cpuset[arg.num_threads];

    for (int i = 0; i < arg.num_threads; i++)
    {
        CPU_ZERO(cpuset + i);
        CPU_SET(i % num_cpus, cpuset + i);
        pthread_create(&threads[i], NULL, &load_and_initialize_threads, (void *)NULL);
        if (pthread_setaffinity_np(threads[i], sizeof(cpu_set_t), cpuset + i) < 0)
        {
            LOG(WARNING)<<"CPU Affinity not set. cpu "<<(i % num_cpus)<<", thread "<<i;
        }
    }

    LOG(INFO)<<"TOTAL THREAD NUMBER IS: "<<arg.num_threads;

    while (!isStopped())
    {
        /* receive task frome queue */
        message = m_scheduler.pop();
        if (isStopped() || message == NULL)
        {
            LOG(INFO) << "CPTask is stopped.";
            if (message) free(message);
            break;
        }

        switch (message->header.type)
        {
        case FIFO_DH_REQ_MSG1:
        {   
            int clientfd = message->header.sockfd;
            LOG(INFO) << "process traditional ECDH session connection request";
            if (generate_and_send_session_msg1_resp(clientfd) != 0)
            {
                LOG(ERROR) << "failed to generate and send session msg1 resp.";
                break;
            }
        }
        break;

        case FIFO_DH_MSG2:
        {
            int clientfd = message->header.sockfd;
            SESSION_MSG2 *msg2 = NULL;
            msg2 = (SESSION_MSG2 *)message->msgbuf;
            if (process_exchange_report(clientfd, msg2) != 0)
            {
                LOG(ERROR) << "failed to process exchange_report request.";
                break;
            }
        }
        break;

        case FIFO_DH_CLOSE_REQ:
        {
            int clientfd = message->header.sockfd;
            SESSION_CLOSE_REQ *closereq = NULL;
            closereq = (SESSION_CLOSE_REQ *)message->msgbuf;
            process_close_req(clientfd, closereq);
        }
        break;

        case FIFO_SHIELD_REQ:
        {
            LOG(INFO)<<"rcv msg shield req.";

            sgx_status_t (*ecall_fn)(sgx_enclave_id_t, uint32_t *, uint32_t, uint8_t *, uint32_t) = ecall_message_pass_switchless;
            uint32_t sgx_ret;

            SHIELD_REQ_MSG *shield_req = (SHIELD_REQ_MSG *)message->msgbuf;

            // clock_gettime(CLOCK_MONOTONIC, &start_job_time[shield_req->type]);
            sgx_status_t ret = ecall_fn(e2_enclave_id, &sgx_ret, message->header.sockfd, message->msgbuf, message->header.size);

            if (ret != 0 || sgx_ret != 0)
            {
                LOG(ERROR)<<"ENCLAVE_MSG PASS ERROR, ERROR_CODE IS: 0x" << std::hex<< sgx_ret<< ", return 0x"<<std::hex<<ret; 
            }
        }
        break;

        case FIFO_USER_FILE:
        {
            sgx_status_t (*ecall_fn)(sgx_enclave_id_t, uint32_t *, uint32_t, uint8_t *, uint32_t) = ecall_message_pass_switchless;

            uint32_t sgx_ret;
            USER_FILE_HEADER *file_header = (USER_FILE_HEADER *)message->msgbuf;

            // clock_gettime(CLOCK_MONOTONIC, &start_job_time[0]);

            sgx_status_t ret = ecall_fn(e2_enclave_id, &sgx_ret, message->header.sockfd, file_header->msgbuf, message->header.size);

            if (ret != 0 || sgx_ret != 0)
            {
                LOG(ERROR)<<"ENCLAVE_MSG PASS ERROR, ERROR_CODE IS: 0x"<<std::hex<<sgx_ret<<", sgx return 0x"<<ret;
            }
        }
        break;

        case FIFO_FILE_REQ:
        {
            uint32_t id = message->header.size;
            uint32_t sock = message->header.sockfd;
            LOG(INFO)<<"receiving file req of id: "<< id;
            
            // Get encrypted filename
            char *filename;
            if (get_encrypted_filename(id, &filename) == 0) {
                // Get file size
                FILE *file = fopen(filename, "rb");
                if (file) {
                    fseek(file, 0, SEEK_END);
                    uint32_t file_size = ftell(file);
                    fclose(file);
                    
                    // Send file
                    send_file(sock, filename, file_size);
                } else {
                    LOG(ERROR) << "Failed to open file: " << filename;
                }
                free(filename);
            } else {
                LOG(ERROR) << "Failed to get encrypted filename for id: " << id;
            }
        }
        break;

        // case FIFO_SIG_MSG: // measure key req?
        // {

            // clock_gettime(CLOCK_MONOTONIC, &end_req_time);
            // timespec_sub(&end_req_time, &start_req_time, &req_time);
            // printf("req time: %ld::%010ld..\n", req_time.tv_sec, req_time.tv_nsec);

            // timespec_add(&req_time, &req_res, &req_res);
            // printf("req res: %ld::%010ld..\n", req_time.tv_sec, req_time.tv_nsec);
        // }
        // break;

        default:
        {
            LOG(ERROR)<<"server rcv Unkown message, header type is "<<message->header.type;
        }
        break;
        }

        free(message);
        message = NULL;
    }

    /* Shield Store finish */
    for (int i = 0; i < arg.num_threads; i++)
    {
        pthread_join(threads[i], (void **)&status);
    }

    free(threads);
    sgx_destroy_enclave(e2_enclave_id);
}

void CPTask::shutdown()
{
    stop();
    m_scheduler.close();
    join();
}

void CPTask::puttask(FIFO_MSG *requestData)
{
    if (isStopped())
    {
        return;
    }

    m_scheduler.push(requestData);
}
