// Enclave3.cpp : Defines the exported functions for the .so application
#include <map>
#include <typeinfo>

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "sgx_utils.h"
#include "sgx_tprotected_fs.h"

#include "error_codes.h"
#include "datatypes.h"
#include "Utility_E3.h"

#include "GWAS.h"
#include "EnclaveExecutor_t.h"
#include "EnclaveMessageExchange.h"

#define UNUSED(val) (void)(val)
#define RESPONDER_PRODID 1
// std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;
std::map<uint32_t, sgx_key_128bit_t*>key_info_map;

dh_session_t g_session;

// This is hardcoded responder enclave's MRSIGNER for demonstration purpose. The content aligns to responder enclave's signing key
sgx_measurement_t g_responder_mrsigner = {
	{
		0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14, 0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43,
		0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c, 0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e
	}
};

extern "C" uint32_t enclave_create_session_with_server(uint32_t *session_id){
    uint32_t ret = create_session(&g_session);
    memcpy(session_id, &(g_session.session_id), sizeof(uint32_t));
    return ret;
}


/* Function Description:
 *   This is to verify peer enclave's identity.
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable: it's INITIALIZED'ed enclave; in non-debug build configuration, the enclave isn't loaded with enclave debug mode.
 **/
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity){
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
}


void ecall_print_mrsigner(){
    UNUSED(0);
}

uint32_t ecall_executor_close_session(){
    ATTESTATION_STATUS ke_status = SUCCESS;
    ke_status = close_session(&g_session);
    //Erase the session context
    memset(&g_session, 0, sizeof(dh_session_t));
    return ke_status;
}


uint32_t session_decrypt_secure_msg(secure_message_t *resp_data, uint32_t resp_size, uint8_t **decrypted_msg, uint32_t *decrypted_length){
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
    if(!decrypted_data){
        printf("NO decrypted data;\n");
        return MALLOC_ERROR;
    }

    memset(decrypted_data, 0, decrypted_data_length);

    const uint8_t* plaintext = (const uint8_t*)("");
    uint32_t plaintext_length = 0;

    status = sgx_rijndael128GCM_decrypt(&g_session.active.AEK, 
                resp_data->message_aes_gcm_data.payload, decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(resp_data->message_aes_gcm_data.reserved)),
                sizeof(resp_data->message_aes_gcm_data.reserved), 
                &(resp_data->message_aes_gcm_data.payload[decrypted_data_length]), plaintext_length,
                &resp_data->message_aes_gcm_data.payload_tag);

    if(status!=SGX_SUCCESS){
        SAFE_FREE(decrypted_data);
        return status;
    }

    // Verify if the nonce obtained in the request is equal to the session nonce
    if(*((uint32_t*)resp_data->message_aes_gcm_data.reserved) != g_session.active.counter || 
        *((uint32_t*)resp_data->message_aes_gcm_data.reserved) > ((uint32_t)-2)){
        SAFE_FREE(decrypted_data);
        return INVALID_PARAMETER_ERROR;
    }

    *decrypted_msg = decrypted_data;
    memcpy(decrypted_length, &decrypted_data_length, sizeof(uint32_t));
    return SUCCESS;
}



ATTESTATION_STATUS ecall_add_aek(secure_message_t *resp_data, uint32_t resp_size){
    uint32_t ret, msg_length;
    uint8_t *decrypted_data;


    ret = session_decrypt_secure_msg(resp_data, resp_size, &decrypted_data, &msg_length);

    if (ret != 0){
        return ERROR_UNEXPECTED;
    }
    
    /* ADD PROPOSAL GRANT TO GWAS. */
    proposal_grant *key_info = (proposal_grant *)decrypted_data;
    SAFE_FREE(decrypted_data);

    return SUCCESS;
}


ATTESTATION_STATUS ecall_batch_add_aek(secure_message_t *resp_data, uint32_t resp_size){
    uint32_t ret, msg_length, f_ret;
    uint8_t *decrypted_data;

    ret = session_decrypt_secure_msg(resp_data, resp_size, &decrypted_data, &msg_length);

    if (ret != 0){
        return ERROR_UNEXPECTED;
    }

    batch_proposal_grant *key_info = (batch_proposal_grant *)decrypted_data;
    uint32_t data_num = key_info->data_num;

    uint32_t *return_ids = (uint32_t *) key_info->buf;
    uint8_t *keys = (uint8_t *)(key_info->buf + data_num*sizeof(uint32_t));

    for(int i=0; i<data_num; i++)
    {
        // printf("---------------------------------> receiving data_id: %d,", return_ids[i] );
        // show_ut(keys+i*16, 16, "receiving derivation keys: ");
        // printf("#############################\n###########################\n");

        sgx_key_128bit_t *rcv_key = (sgx_key_128bit_t*)malloc(MAC_KEY_SIZE);
        if (!rcv_key) return MALLOC_ERROR;
        memcpy(rcv_key, keys+i*MAC_KEY_SIZE, MAC_KEY_SIZE);

        key_info_map[return_ids[i]] = rcv_key;        
    }
    
    SAFE_FREE(decrypted_data);
    return SUCCESS;
}


uint32_t ecall_run_gwas(uint32_t id, uint8_t *content, uint32_t content_len)
{
    uint32_t plaintext_size, data_id;

    auto it = key_info_map.find(id);
    if (it == key_info_map.end())
    {
        return NULL_ERROR;
    }

    sgx_key_128bit_t *key = it->second;

    if (!key)
    {
        return NULL_ERROR;
    }

    secure_message_t *encrypted_file = reinterpret_cast<secure_message_t *>(content);
    data_id = encrypted_file->session_id;

    uint8_t *plaintext;
    uint32_t ret_status = decrypt_secure_msg(encrypted_file, content_len, &plaintext, &plaintext_size, (sgx_key_128bit_t*)key);

    if (add_snp(plaintext, plaintext_size) != 0) return SGX_FILE_ERROR;

    // uint8_t hweRes;
    // cal_hwe(201219770, &hweRes);

    free(plaintext);
    return SUCCESS;
}




