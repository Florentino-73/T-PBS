
#include "datatypes.h"
#include "sgx_eid.h"
#include "sgx_trts.h"
#include <map>
#include "dh_session_protocol.h"

#ifndef LOCALATTESTATION_H_
#define LOCALATTESTATION_H_

#ifdef __cplusplus
extern "C" {
#endif
uint32_t SGXAPI create_session(dh_session_t *p_session_info, sgx_enclave_id_t wasm_vm_enclave_id);
uint32_t SGXAPI send_request_receive_response(dh_session_t *p_session_info, char *inp_buff, size_t inp_buff_len, size_t max_out_buff_size, char **out_buff, size_t* out_buff_len, sgx_enclave_id_t wasm_vm_enclave_id);
uint32_t SGXAPI close_session(dh_session_t *p_session_info, sgx_enclave_id_t wasm_vm_enclave_id);
uint32_t SGXAPI send_user_req(dh_session_t *session_info, size_t max_out_buff_size, char **out_buff, size_t* out_buff_len, sgx_enclave_id_t wasm_vm_enclave_id);
uint32_t SGXAPI send_user_data(dh_session_t *session_info, char *inp_buff, size_t inp_buff_len, secure_message_t *out_buff, size_t out_buff_len);

uint32_t session_decrypt(dh_session_t *session_info, secure_message_t *secure_msg, uint32_t cipher_length, uint8_t **plaintext, uint32_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif
