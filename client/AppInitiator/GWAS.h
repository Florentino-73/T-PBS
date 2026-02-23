#include <iostream>
#include <cstdlib>
#include <map>
#include <cstddef>
#include <vector>
#include <openssl/sha.h>


#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_dh.h"
#include "dh_session_protocol.h"

#include "error_codes.h"
#include "datatypes.h"


#ifndef GWAS_APP_H
#define GWAS_APP_H

#define ENCLAVE_GWAS_NAME "libenclave_executor.signed.so" 

void show_ut(const uint8_t *var, size_t length, const char *fmt);

class GWAS_EXECUTOR{
private:
    bool flag;
    sgx_enclave_id_t gwas_enclave_id=0;
    uint32_t session_id;

    uint32_t generate_key_req(uint32_t batch_id, uint32_t data_num, const char *data_content, uint32_t *data_length, unsigned char *resp_key_req);
    uint32_t generate_insert_req(uint32_t batch_id, uint32_t data_num, const char *data_content, uint32_t *data_length, unsigned char* resp_add_req);

public:
    GWAS_EXECUTOR(bool _flag=false);
    ~GWAS_EXECUTOR();

    uint32_t insert_hash_req(uint32_t batch_id, uint32_t pid, uint32_t data_num, const char *data_content, uint32_t *data_length);
    uint32_t get_key(uint32_t batch_id, uint32_t pid, uint32_t data_num, const char *data_content, uint32_t *data_length, char **secure_resp, uint32_t *secure_msg_size);
    uint32_t client_update_hash_then_get_key(uint32_t batch_id, uint32_t pid, secure_message_t **encrypted_key, uint32_t *encrypted_key_size);

    uint32_t req_wrapper_and_send(uint32_t page_id, std::vector<uint32_t> &vec_ids, uint32_t req_budget, char **secure_resp, uint32_t *secure_msg_size, uint32_t req_type);

    
    uint32_t add_key(secure_message_t *encrypted_key, uint32_t encrypted_key_size);
    uint32_t run_gwas(uint32_t id);
    
};

#endif




