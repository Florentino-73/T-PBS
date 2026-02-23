#include <map>
#include <unistd.h>
#include <stdio.h>
#include <iomanip>
#include <sched.h>
#include <sys/sysinfo.h>
#include <sstream>

#include "sgx_eid.h"
#include "sgx_urts.h"

#include "fifo_def.h"
#include "datatypes.h"
#include "error_codes.h"
#include "AppInitiator.h"
#include "EnclaveInitiator_u.h"
#include "UntrustedEnclaveMessageExchange.h"

#include "benchmark.h"
#define ENCLAVE_INITIATOR_NAME "libenclave_initiator.signed.so"

uint32_t ENTRY_PAGE_SIZE = 1024;
sgx_enclave_id_t initiator_enclave_id = 0;


void ocall_printf(const char *str)
{
    LOG(INFO)<<str;
}


int main(int argc, char* argv[])
{
    int update = 0;
    uint32_t ret_status, enc_data_len, session_id;
    sgx_status_t status;
    sgx_launch_token_t token = {0};

    (void)argc;
    (void)argv;

    uint32_t maxId = 10000;
    uint32_t reqNum = 100;
    bool getFileFlag = false;
    bool GWASflag = false;

    if (argc >= 2)
    {
        for(int i=1; i<argc; i++)
        {
            std::string t_arg = std::string(argv[i]);
            if (t_arg == "--maxId")
            {
                maxId = atoi(argv[++i]);
            }
            else if (t_arg == "--reqNum")
            {
                reqNum = atoi(argv[++i]);
            }
            else if (t_arg == "--getFile")
            {
                getFileFlag = true;
            }
            else if (t_arg == "--runGWAS")
            {
                GWASflag = true;
            }
            else if (t_arg == "--pageSize")
            {
                ENTRY_PAGE_SIZE = atoi(argv[++i]);
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
    // std::stringstream logSuffix;
    // logSuffix << "m"<<maxId<<"n"<<reqNum<<"p"<<ENTRY_PAGE_SIZE<<"-client";

    // std::stringstream logSuffix;
    // logSuffix <<"server_p"<<pageSize<<"t"<<numThreads<<"c"<<managerCap;

    // printf("ready to log in suffix %s.\n" , logSuffix.str().c_str());
    // google::SetLogFilenameExtension(logSuffix.str().c_str());
    // google::SetLogDestination(google::GLOG_INFO, logDir.str().c_str());

    google::SetLogFilenameExtension("client");
    google::InitGoogleLogging("client"); // init logging 
    //printf("LOG DIR is: %s.\n", FLAGS_log_dir.c_str());

    LOG(WARNING)<<"maximum data id: "<< maxId;
    LOG(WARNING)<<"input request data num: "<< reqNum;
    LOG(WARNING)<<"getFile is "<< getFileFlag;
    LOG(WARNING)<<"Run GWAS is "<< GWASflag;
    LOG(WARNING)<<"get entry page size: "<< ENTRY_PAGE_SIZE;

    // create ECDH initiator enclave
    status = sgx_create_enclave(ENCLAVE_INITIATOR_NAME, 1, &token, &update, &initiator_enclave_id, NULL);

    if (status != SGX_SUCCESS) 
    {
        printf("failed to load enclave %s, error code is 0x%x.\n", ENCLAVE_INITIATOR_NAME, status);
        return -1;
    }

    LOG(INFO)<<"succeed to load enclave: "<<ENCLAVE_INITIATOR_NAME;

    // create ECDH session using initiator enclave, it would create ECDH session with responder enclave running in another process
BENCHMARK_START(attest);
    status = ecall_create_session(initiator_enclave_id, &ret_status, &session_id);
BENCHMARK_STOP(attest);

    if (status != SGX_SUCCESS || ret_status != 0) 
    {
        printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }
LOG(WARNING)<<"attest time: "<<attest.tv_sec<<"::"<<std::setw(9)<<attest.tv_nsec;


    if (getFileFlag)
    {
        for (int id=1; id<=maxId; id++)
        { 
            get_file_req(id);
        }
    }
    
    /* BEGIN: client request data. */
    LOG(INFO)<<"start request data";

    uint32_t request_budget = 1;
BENCHMARK_START(request);
    ret_status = client_req_asyn_data(maxId, reqNum, GWASflag);
BENCHMARK_STOP(request);

    if (ret_status != SGX_SUCCESS)
    {
        printf("error when client request for data. error code is: 0x%x.\n", ret_status);
        return -1;
    }

LOG(WARNING)<<"Data num "<<reqNum <<", client total req time: "<<request.tv_sec<<"::"<<std::setw(9)<<request.tv_nsec;


    // close ECDH session
    status = ecall_close_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("ecall_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }



    sgx_destroy_enclave(initiator_enclave_id);

    LOG(WARNING)<<"Succeed to close Session...";
    google::ShutdownGoogleLogging();


    return 0;
}
 
