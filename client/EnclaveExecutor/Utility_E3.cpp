#include <stdio.h>      /* vsnprintf */
#include "stdlib.h"
#include "string.h"

#include "sgx_eid.h"

#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E3.h"
#include "EnclaveExecutor_t.h"

#ifdef _LOG
    extern "C" void printf(const char *fmt, ...)
    {
        char buf[BUFSIZ] = {'\0'};
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, BUFSIZ, fmt, ap);
        va_end(ap);
        ocall_printf(buf);
    }
#endif

void PRINT_BYTE_ARRAY(void *mem, uint32_t len)
{
    (void)mem;
    (void)len;
}

void show_ut(const uint8_t *var, size_t length, const char *fmt){
    (void)var;
    (void)length;
    (void)fmt;
}



uint32_t decrypt_secure_msg(secure_message_t *resp_data, uint32_t resp_size, uint8_t **decrypted_msg, uint32_t *decrypted_length, const sgx_key_128bit_t *key){
    uint32_t plain_text_offset, expected_payload_size, decrypted_data_length;
    uint8_t l_tag[TAG_SIZE];
    uint8_t *decrypted_data;
    sgx_status_t status;

    /* DECRYPT RESP_DATA */
    decrypted_data_length = resp_data->message_aes_gcm_data.payload_size;
    expected_payload_size = resp_size - sizeof(secure_message_t);

    if (expected_payload_size != decrypted_data_length ){
        // note: decrypted datalength = 0;
        return INVALID_PARAMETER;
    }

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data) return NULL_ERROR;

    memset(decrypted_data, 0, decrypted_data_length);

    const uint8_t* plaintext = (const uint8_t*)("");
    uint32_t plaintext_length = 0;

    status = sgx_rijndael128GCM_decrypt(key, 
                resp_data->message_aes_gcm_data.payload, decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(resp_data->message_aes_gcm_data.reserved)),
                sizeof(resp_data->message_aes_gcm_data.reserved), 
                &(resp_data->message_aes_gcm_data.payload[decrypted_data_length]), plaintext_length,
                &resp_data->message_aes_gcm_data.payload_tag);

    if(status!=SGX_SUCCESS){
        SAFE_FREE(decrypted_data);
        return status;
    }

    *decrypted_msg = decrypted_data;
    memcpy(decrypted_length, &decrypted_data_length, sizeof(uint32_t));
    
    return SUCCESS;
}


const uint32_t filename_size = 100;
uint32_t get_encrypted_filename(uint32_t data_id, char **new_filename){
    char *filename = (char *)malloc(filename_size);
    memset(filename, 0, filename_size);
    snprintf(filename, filename_size, "../test_data/gwas_encrypted/%08x.gwas", data_id);
    *new_filename = filename;
    return 0;
}
