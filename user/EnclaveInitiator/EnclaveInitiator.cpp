// Enclave1.cpp : Defines the exported functions for the .so application
#include <map>
// #include "string.h"
#include <typeinfo>
#include "sgx_tprotected_fs.h"

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "sgx_utils.h"

#include "error_codes.h"
#include "Utility_E1.h"
#include "EnclaveInitiator_t.h"
#include "EnclaveMessageExchange.h"

#define UNUSED(val) (void)(val)

#define RESPONDER_PRODID 1



std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

dh_session_t g_session;

// This is hardcoded responder enclave's MRSIGNER for demonstration purpose. The content aligns to responder enclave's signing key
sgx_measurement_t g_responder_mrsigner = {
	{
		0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14, 0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43,
		0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c, 0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e
	}
};


const uint32_t filename_size = 42;
uint32_t get_encrypted_filename(uint32_t data_id, char **new_filename){
    char *filename = (char *)malloc(filename_size);
    memset(filename, 0, filename_size);
    snprintf(filename, filename_size, "../test_data/gwas_encrypted/%08x.gwas", data_id);
    *new_filename = filename;

    return SUCCESS;
}

/* Function Description:
 *   This is ECALL routine to create ECDH session.
 *   When it succeeds to create ECDH session, the session context is saved in g_session.
 * */
extern "C" uint32_t ecall_create_session(uint32_t *session_id){
    uint32_t status = create_session(&g_session, 0); // Use 0 as placeholder for wasm_vm_enclave_id

    memcpy(session_id, &(g_session.session_id), sizeof(uint32_t));
    return status;
}


/* Function Description:3
 *   This is ECALL interface to close secure session*/
uint32_t ecall_close_session(){
    ATTESTATION_STATUS ke_status = SUCCESS;
    ke_status = close_session(&g_session, 0); // Use 0 as placeholder for wasm_vm_enclave_id
    //Erase the session context
    memset(&g_session, 0, sizeof(dh_session_t));
    return ke_status;
}


uint32_t ecall_get_data_id(uint32_t *data_id){
    ATTESTATION_STATUS ke_status=SUCCESS;
    // uint32_t target_fn_id, msg_type, msg_length;
    char* out_buff;
    size_t out_buff_len;
    size_t max_out_buff_size = 100;
    resp_user_data *meta_data; // data to store data id & (pk, sk);


    ke_status = send_user_req(&g_session, max_out_buff_size, &out_buff, &out_buff_len, 0); // Use 0 as placeholder for wasm_vm_enclave_id
    
    if (ke_status != SUCCESS) return ke_status;    
    if(!out_buff) return INVALID_PARAMETER_ERROR;
    
    meta_data = (resp_user_data *)out_buff;
    memcpy(data_id, &(meta_data->data_id), sizeof(uint32_t));
    return SUCCESS;
}

/* Function Description:
 *   This is to verify peer enclave's identity.
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable: it's INITIALIZED'ed enclave; in non-debug build configuration, the enclave isn't loaded with enclave debug mode.
 **/
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity){
#ifdef SGX_MODE_SIM
    return SUCCESS;
#else
    if (!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;

    // check peer enclave's MRSIGNER
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_responder_mrsigner, sizeof(sgx_measurement_t)))
        return ENCLAVE_TRUST_ERROR;

    // check peer enclave's product ID and enclave attribute (should be INITIALIZED'ed)
    if (peer_enclave_identity->isv_prod_id != RESPONDER_PRODID || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;

    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
    	return ENCLAVE_TRUST_ERROR;
#endif

    return SUCCESS;
#endif
}

/* Function Description: Operates on the input secret and generate the output secret
 * */
uint32_t get_message_exchange_response(uint32_t inp_secret_data){
    uint32_t secret_response;

    //User should use more complex encryption method to protect their secret, below is just a simple example
    secret_response = inp_secret_data & 0x11111111;
    return secret_response;
}

// encrypt enc_data; generate req_message;
uint32_t ecall_send_user_data(char *inp_buff, size_t inp_buff_len, secure_message_t *out_buff, size_t out_buff_len){
    ATTESTATION_STATUS ke_status=SUCCESS;
    if (!out_buff || !inp_buff){
        return INVALID_ARGUMENT;
    }

    // printf("ecall send user data with session id. %d\n", g_session.session_id);
    ke_status = send_user_data(&g_session, inp_buff, inp_buff_len, out_buff, out_buff_len);  
    if (ke_status != SUCCESS){
        return ke_status;
    }

    // memcpy(session_id, &(g_session.session_id), 4);

    return SUCCESS;
}




const uint8_t kAES_256_GCM_KEY[16] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      };


 uint32_t ecall_decrypt_key_encrypt_file(uint8_t *secure_resp, uint32_t secure_msg_size, uint8_t *content, uint32_t file_size, secure_message_t *encrypted_out_buff, uint32_t out_size, uint32_t *data_id){
    if (!secure_resp){
        return NULL_ERROR;
    }

    proposal_grant *key_info;
    uint8_t *decrypted_key;
    uint32_t key_len;
    secure_message_t *enc_tmp;

    uint32_t status = session_decrypt(&g_session, (secure_message_t *)secure_resp, secure_msg_size, (uint8_t **)&key_info, &key_len);
    if (status != SUCCESS){
    }

    if (key_len != sizeof(proposal_grant)){
        return ERROR_TAG_MISMATCH;
    }

    

    if (!content || !encrypted_out_buff){
        return NULL_ERROR;
    }
    if (!data_id || !secure_resp){
        return NULL_ERROR;
    }


    memcpy(data_id, &(key_info->data_id), 4);
    
    status = rijndael_content_encrypt(content, file_size, &enc_tmp, (sgx_key_128bit_t*)key_info->aek, key_info->data_id); // (sgx_key_128bit_t*)kAES_256_GCM_KEY ->aek

    if (status != SUCCESS){
        return ENCRYPT_DECRYPT_ERROR;
    }
    SAFE_FREE(key_info);
    memcpy(encrypted_out_buff, enc_tmp, out_size);
    SAFE_FREE(enc_tmp);
    return status;
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



