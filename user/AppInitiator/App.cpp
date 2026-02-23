#include <map>
#include <ctime>
#include "omp.h"
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <ctime>
#include <random>

#include <iomanip>
#include "sgx_eid.h"
#include "sgx_urts.h"

#include "benchmark.h"
#include "GWAS.h"
#include "fifo_def.h"
#include "datatypes.h"
#include "EnclaveInitiator_u.h"
#include "UntrustedEnclaveMessageExchange.h"

#include <glog/logging.h>

#define ENCLAVE_INITIATOR_NAME "libenclave_initiator.signed.so"

const uint32_t filename_size = 41;
sgx_enclave_id_t initiator_enclave_id = 0;
uint32_t session_id;

uint32_t encrypt_file(uint8_t *encrypted_key, uint32_t encrypted_size, const char *filename, char **ret_filename, uint32_t *ret_file_size, uint32_t *id)
{
    if (!encrypted_key)
    {
        return NULL_ERROR;
    }

    uint32_t file_size, enc_file_size, ret_status, data_id;
    char *new_filename;

    FILE *file = fopen(filename, "rb");
    if (file == NULL)
        return FILE_ERROR;

    fseek(file, 0, SEEK_END);
    file_size = (uint32_t)ftell(file);
    rewind(file);

    uint8_t *content = (uint8_t *)malloc(file_size);
    if (!content)
        return MALLOC_ERROR;
    ret_status = fread(content, 1, file_size, file);
    if (ret_status != file_size)
        return FILE_ERROR;
    fclose(file);

    enc_file_size = sizeof(secure_message_t) + file_size;
    secure_message_t *encrypted_buff = (secure_message_t *)malloc(enc_file_size);
    if (!encrypted_buff)
        return MALLOC_ERROR;

    sgx_status_t status = ecall_decrypt_key_encrypt_file(initiator_enclave_id, &ret_status, (uint8_t *)encrypted_key, encrypted_size, content, file_size, encrypted_buff, enc_file_size, &data_id);

    if (status != SGX_SUCCESS || ret_status != 0)
    {
        printf("ecall encrypt decrypt error, sgx status %x, ret value is %x\n", status, ret_status);
        return ENCRYPT_DECRYPT_ERROR;
    }

    LOG(INFO)<<"From server, recv data id: "<<data_id;
    
    free(content);
    get_encrypted_filename(data_id, &new_filename);

    file = fopen(new_filename, "w+b");
    ret_status = fwrite(encrypted_buff, 1, enc_file_size, file);
    if (ret_status != enc_file_size)
        return FILE_ERROR;
    fclose(file);

    free(encrypted_buff);

    *ret_filename = new_filename;
    memcpy(id, &data_id, sizeof(uint32_t));
    memcpy(ret_file_size, &enc_file_size, sizeof(uint32_t));

    return SUCCESS;
}

int send_snp(uint32_t id, uint32_t budget)
{
    /* BEGIN: process GWAS  */
    uint32_t enc_data_len;
    size_t out_buff_len;

    uint32_t ret_status;
    sgx_status_t status;
    secure_message_t *out_buff;
    uint32_t filename_size;

    if (id < 10)
    {
        filename_size = SNP_FILENAME_SIZE - 3;
    }
    else if (id < 100)
    {
        filename_size = SNP_FILENAME_SIZE - 2;
    }
    else
        filename_size = SNP_FILENAME_SIZE - 1;

    char *filename = (char *)malloc(filename_size);
    memset(filename, 0, filename_size);
    snprintf(filename, filename_size - 1, "../test_data/bin/case_%d.bin", id);

    enc_user_data *data_capsule = NULL;
    ret_status = process_snp_data(filename, budget, &data_capsule, &enc_data_len);
    if (ret_status != 0)
    {
        printf("Failed to process snp data. \n");
        return -1;
    }
    /* END: process GWAS */

    /*  BEGIN: encrypt && send enc_user_data; */
    out_buff_len = sizeof(secure_message_t) + enc_data_len;
    out_buff = (secure_message_t *)malloc(out_buff_len);
    if (!out_buff)
    {
        printf("Error: out_buff malloc() fail ...\n");
        return -1;
    }

    status = ecall_send_user_data(initiator_enclave_id, &ret_status, (char *)data_capsule, enc_data_len, out_buff, out_buff_len); // encrypt user_data

    if (status != SGX_SUCCESS || ret_status != 0)
    {
        printf("error when send user data: ecall return 0x%x. error code is 0x%x.\n", status, ret_status);
        sgx_destroy_enclave(initiator_enclave_id);
        free(out_buff);
        free(data_capsule);
        return -1;
    }

    free(data_capsule);

    ret_status = wrap_and_send_user_data(session_id, out_buff, out_buff_len); // send unencrypted user data.
    if (ret_status != 0)
    {
        printf("wrap & send data error.\n");
        free(out_buff);
        return -1;
    }

    free(out_buff);
    /* END: encrypt && send enc_user_data; */

    return 0;
}

uint32_t key_req(const char *filename, uint32_t budget)
{
    uint32_t ret_status = 0, data_id, enc_file_size;
    FIFO_MSG *msgreq, *msg_resp;
    size_t req_size, resp_size;
    char *new_filename;

    ret_status = gen_file_req_header(session_id, &msgreq, &req_size);
    if (ret_status != 0)
        return ret_status;

BENCHMARK_START(reqKey);
    int ret = client_send_receive(msgreq, req_size, &msg_resp, &resp_size);
BENCHMARK_STOP(reqKey);
    if ( ret != 0)
    {
        free(msgreq);
        LOG(ERROR)<<"Failed send or receive user data.";
        return INVALID_SESSION;
    }
LOG(WARNING)<<"file req key time: "<<reqKey.tv_sec<<"::"<<std::setw(9)<<reqKey.tv_nsec;

    if (msg_resp->header.type != FIFO_CLIENT_ACK)
    {
        LOG(INFO)<<"RETURN REJ";
        free(msg_resp);
        free(msgreq);
        return SERVER_REJ;
    }

    free(msgreq);
    ret_status = encrypt_file(msg_resp->msgbuf, msg_resp->header.size, filename, &new_filename, &enc_file_size, &data_id);
    free(msg_resp);

    LOG(INFO)<<"encrypt file, filename: "<<new_filename;
    LOG(WARNING)<<"current data_id is: "<<data_id;
    FIFO_MSG *req_msg, *resp; // header request and resp;
    uint32_t file_req_size;
    if (create_file_header(data_id, budget, enc_file_size, session_id, (char **)&req_msg, &file_req_size) != 0)
        return MALLOC_ERROR;

    LOG(INFO)<<"sending file header";

    // send_data_id and encrypted file;
BENCHMARK_START(uploadBgt);
    ret = client_send_file(req_msg, file_req_size, new_filename, &resp, &resp_size);
BENCHMARK_STOP(uploadBgt);
    if ( ret != 0)
    {
        free(req_msg);
        LOG(ERROR)<<"sending file failed";
        return SERVER_REJ;
    }
LOG(WARNING)<<"file upload bgt time: "<<uploadBgt.tv_sec<<"::"<<std::setw(9)<<uploadBgt.tv_nsec;
    free(req_msg);


    free(resp);
    free(new_filename);
    return 0;
}

uint32_t read_file(uint32_t id)
{
    char *filename = "../test_data/gwas/client_1.gwas";
    uint32_t file_size, ret_status;
    SNP *snp;

    // get_encrypted_filename(id, &filename);
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf("FILE OPEN ERROR %s.\n", strerror(errno));
        return FILE_ERROR;
    }
    fseek(file, 0, SEEK_END);
    file_size = (uint32_t)ftell(file);
    rewind(file);

    uint8_t *content = (uint8_t *)malloc(file_size);
    if (!content)
        return MALLOC_ERROR;
    ret_status = fread(content, 1, file_size, file);
    if (ret_status != file_size)
    {
        return FILE_ERROR;
    }
    fclose(file);

    for (uint8_t *p = content; p < content + file_size; p += sizeof(SNP))
    {
        snp = (SNP *)p;
    }

    return SUCCESS;
}

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL); // Disable buffering
    int update = 0;
    uint32_t ret_status, enc_data_len;
    sgx_status_t status;
    sgx_launch_token_t token = {0};

    (void)argc;
    (void)argv;
    std::random_device seed;	
	srand(seed());

    // int total_num = 5000;
    int total_num = 2;
    if (argc >= 2)
    {
        for(int i=1; i<argc; i++)
        {
            std::string t_arg = std::string(argv[i]);
            if (t_arg == "-n")
            {
                total_num = atoi(argv[++i]);
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
    google::SetLogFilenameExtension("user");
    // FLAGS_alsologtostderr = true;
    google::InitGoogleLogging("user"); // init logging 

    LOG(WARNING)<<" input total num: "<<total_num;

    // create ECDH initiator enclave
    status = sgx_create_enclave(ENCLAVE_INITIATOR_NAME, SGX_DEBUG_FLAG, &token, &update, &initiator_enclave_id, NULL);
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
LOG(WARNING)<<"Establish secure channal cost: "<<attest.tv_sec<<"::"<<std::setw(9)<<attest.tv_nsec<<", session id is "<<session_id;

    char *filename = (char *)malloc(50);
    for (int ii = 0; ii < total_num; ii++)
    {
        // Use sequential ID from generated_gwas directory
        int id = ii % 5000; // Use ID from 0 to 4999 (matching existing files)
        snprintf(filename, 50, "../test_data/generated_gwas/%08x.gwas", id);
        
        // Use default budget for .gwas files (original format without epsilon)
        uint32_t budget = 8000000; // Default budget: 8 * 1000000

        FILE *f = fopen(filename, "rb");
        if (!f) {
            LOG(WARNING) << "Failed to open file " << filename << ", skipping";
            continue;
        }
        fclose(f);

        LOG(INFO)<<"++++++++++++++++++++++++++++++++ start key req id "<<id<<", sending file "<<filename << ", budget: " << budget;

BENCHMARK_START(req);
        key_req(filename, budget);
BENCHMARK_STOP(req);
LOG(WARNING)<<"TOTAL UPLOAD data and bgt time is "<<req.tv_sec<<"::"<<std::setw(9)<<req.tv_nsec;
    }
    free(filename);

    clock_t AfterKeyReq = clock();

    // close ECDH session
    status = ecall_close_session(initiator_enclave_id, &ret_status);

    clock_t AfterCloseSession = clock();

    if (status != SGX_SUCCESS || ret_status != 0)
    {
        printf("ecall_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }

    sgx_destroy_enclave(initiator_enclave_id);
    return 0;
}
