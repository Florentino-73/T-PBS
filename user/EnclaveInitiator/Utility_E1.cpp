

#include "Utility_E1.h"

#include <stdio.h>      /* vsnprintf */
#ifdef _LOG
    void printf(const char *fmt, ...)
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
    if(!mem || !len)
    {
        return;
    }
    uint32_t *array = (uint32_t *)mem;
    printf("%u bytes:\n{\n", len); // %u: unsigned deci
    uint8_t i = 0;
    for(i = 0; i < len - 1; i++)
    {   
        printf("0x%x, ", array[i]); // %x: unsigned hex
        if(i % 8 == 7) printf( "\n");
    }
}

void show_ut(const uint8_t *var, size_t length, const char *fmt){
    for (int i=0; i<length; i++){
    }
}


uint32_t rijndael_content_encrypt(uint8_t *content, uint32_t data2encrypt_len, secure_message_t **out_buff, sgx_key_128bit_t *key, uint32_t counter){

    if (!content||!key) return NULL_ERROR;

    sgx_status_t status;
    const uint8_t* plaintext = (const uint8_t*)("");
    size_t plaintext_length = 0;
    size_t buff_len = sizeof(secure_message_t) + data2encrypt_len;

    secure_message_t *req_message;
    req_message = (secure_message_t *)malloc(buff_len);
    if(!req_message) return MALLOC_ERROR;
    memset(req_message, 0, buff_len);

    //Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_len;
    //Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved, &counter, sizeof(counter));
    //Set the session ID of the message to the current session id
    req_message->session_id = counter;

    //Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(key, 
                content, data2encrypt_len,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), 
                plaintext, plaintext_length,
                &(req_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status){
        SAFE_FREE(req_message);
        return status;
    }
    // memcpy(out_buff, req_message, buff_len);
    *out_buff = req_message;
    // SAFE_FREE(req_message);
    return SUCCESS;
}

// NOTE: MAY HAVE BUG
uint32_t test_decrypt(sgx_key_128bit_t *key, secure_message_t *resp_data, uint32_t resp_size){
uint32_t plain_text_offset, expected_payload_size, decrypted_data_length;
    uint8_t l_tag[TAG_SIZE];
    uint8_t *decrypted_data;
    sgx_status_t status;

    /* DECRYPT RESP_DATA */
    decrypted_data_length = resp_data->message_aes_gcm_data.payload_size;
    expected_payload_size = resp_size - sizeof(secure_message_t);

    if (expected_payload_size != decrypted_data_length ){
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
    // NOTE:CAN RETURN DECRYPTED_DATA;
    SAFE_FREE(decrypted_data);
    return SUCCESS;
}