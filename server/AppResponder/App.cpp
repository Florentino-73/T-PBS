#include "UntrustedEnclaveMessageExchange.h"
// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <sstream>
#include <signal.h>
#include "EnclaveResponder_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_quote_3.h"

#include "fifo_def.h"
#include "datatypes.h"
#include "config.h"       

#include "CPTask.h"
#include "CPServer.h"
#include "../Include/error_codes.h"
#include <glog/logging.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define UNUSED(val) (void)(val)
#define TCHAR char
#define _TCHAR char
#define _T(str) str
#define scanf_s scanf
#define _tmain main

CPTask *g_cptask = NULL;
CPServer *g_cpserver = NULL;

// Pre-initialize DCAP by loading PCE and QE3 BEFORE loading the application enclave
// This avoids the issue of loading PCE from within an OCALL context
void pre_init_dcap()
{
    quote3_error_t qe3_ret;
    sgx_target_info_t qe_target_info;
    
    qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG(WARNING) << "sgx_qe_set_enclave_load_policy failed: 0x" << std::hex << qe3_ret;
    }
    
    if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so")) {
        sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so");
    }
    
    if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so")) {
        sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so");
    }
    
    if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1")) {
        sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
    }
    
    // Actually load PCE and QE3 by calling sgx_qe_get_target_info
    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG(WARNING) << "sgx_qe_get_target_info failed: 0x" << std::hex << qe3_ret << ", DCAP quote generation may fail later.";
    }
}

// extern timespec *start_job_time, *end_job_time, *res_job_time, *total_job_time;

void client_msg_return(int ret, int client_sock, uint32_t msg_size, char *msg, int job_type)
{
    FIFO_MSG *fifo_resp = NULL;
    uint32_t ret_size = (uint32_t)sizeof(FIFO_MSG) + msg_size;

    if (ret != 0) // return reject
    {
        fifo_resp = (FIFO_MSG *)malloc(ret_size);
        if (!fifo_resp) return;
        memset(fifo_resp, 0, ret_size);
        fifo_resp->header.type = FIFO_CLIENT_REJ;
        fifo_resp->header.size = msg_size;
        if (msg && msg_size > 0)
            memcpy(fifo_resp->msgbuf, msg, msg_size);
        LOG(INFO) << "budget request receive reject";
    }
    else // return success, return msg
    {
        fifo_resp = (FIFO_MSG *)malloc(ret_size);
        if (!fifo_resp) return;
        memset(fifo_resp, 0, ret_size);
        fifo_resp->header.type = FIFO_CLIENT_ACK;
        fifo_resp->header.size = msg_size;
        if (msg)
            memcpy(fifo_resp->msgbuf, msg, msg_size);
        LOG(INFO) << "budget request receive ack";
    }

    if (send(client_sock, (char *)fifo_resp, ret_size, 0) <= 0)
    {
        close(client_sock);
        LOG(ERROR) << "error msg return! errno: " << strerror(errno);
    }
    free(fifo_resp);
    return;
}

void user_msg_return(int ret, uint32_t client_sock)
{
    FIFO_MSG *fifo_resp = NULL;
    fifo_resp = (FIFO_MSG *)malloc(sizeof(FIFO_MSG));
    fifo_resp->header.size = 0;
    fifo_resp->header.type = (ret == 0) ? FIFO_USER_DATA_ACK : FIFO_USER_DATA_REJ;

    if (send(client_sock, reinterpret_cast<char *>(fifo_resp), static_cast<int>(sizeof(FIFO_MSG)), 0) == -1)
    {
        LOG(ERROR) << "fail to send response fd " << client_sock << ". errno is: " << strerror(errno);
    }

    free(fifo_resp);
    return;
}

/**
 * Ocall function for allocating untrusted memory
 **/
void *sbrk_o(size_t size)
{
    void *result = NULL;
    result = sbrk((intptr_t)size);
    return result;
}

void ocall_printf(const char *str)
{
    LOG(INFO) << str;
    printf("%s", str);
}

void ocall_print(const char *str)
{
    LOG(INFO) << str;
    printf("%s", str);
}

void signal_handler(int sig)
{
    switch (sig)
    {
    case SIGINT:  // ctrl+C
    case SIGTERM: // kill <PID>
    {
        if (g_cpserver)
            g_cpserver->shutDown();
    }
    break;
    default:
        break;
    }

    exit(1);
}

void cleanup()
{
    if (g_cptask != NULL)
        delete g_cptask;
    if (g_cpserver != NULL)
        delete g_cpserver;
}

// External enclave ID declaration
extern sgx_enclave_id_t e2_enclave_id;

// Forward declaration for DCAP pre-initialization
void pre_init_dcap();

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    // Pre-initialize DCAP to load PCE and QE3 BEFORE loading our enclave
    pre_init_dcap();

    // Load enclave directly in main (do not destroy)
    {
        sgx_launch_token_t test_token = {0};
        int test_update = 0;
        sgx_status_t test_ret = sgx_create_enclave(
            "libenclave_responder.signed.so",
            1, &test_token, &test_update, &e2_enclave_id, NULL);
        if (test_ret != SGX_SUCCESS) {
            printf("Failed to load enclave, error code: 0x%x\n", test_ret);
            return -1;
        }
    }

    int pageSize = 1024;
    int numThreads = 4;  // Reduced from 12 to match TCSNum and CPU cores
    int managerCap = 10;

    if (argc >= 2)
    {
        for(int i=1; i<argc; i++)
        {
            std::string t_arg = std::string(argv[i]);
            if (t_arg == "--pageSize")
            {
                pageSize = atoi(argv[++i]);
            }
            else if (t_arg == "--numThreads")
            {
                numThreads = atoi(argv[++i]);
            }
            else if (t_arg == "--managerCap")
            {
                managerCap = atoi(argv[++i]);
            }
            else if (t_arg == "--logDir")
            {
                google::SetLogDestination(google::GLOG_INFO, argv[++i]);
            }
            else if (t_arg == "--logLevel")
            {
                FLAGS_minloglevel = atoi(argv[++i]);
            }
        }   
    }

    // init logging system
    google::SetLogFilenameExtension("server");
    google::InitGoogleLogging("appserver"); // init logging

#ifdef _LOG
LOG(WARNING)<<"DEFINED LOG";
#endif

    LOG(WARNING)<<"Init Params: pageSize: "<<pageSize<<", numThreads: "<<numThreads<<", managerCap: "<<managerCap;

    // create server instance, it would listen on sockets and proceeds client's requests
    g_cptask = new (std::nothrow) CPTask(pageSize, numThreads, managerCap);
    g_cpserver = new (std::nothrow) CPServer();

    if (!g_cptask || !g_cpserver)
        return -1;

    g_cpserver->setCPTask(g_cptask);    

    atexit(cleanup);

    // register signal handler so to respond to user interception
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    g_cptask->start(); // a new thread start to run CPTask::run();

    if (g_cpserver->init() != 0) // init socket;
    {
        LOG(ERROR) << "fail to init server";
    }
    else
    {
        printf("Server is ON...\n");
        printf("Press Ctrl+C to exit...\n");
        g_cpserver->doWork();
    }

    return 0;
}
