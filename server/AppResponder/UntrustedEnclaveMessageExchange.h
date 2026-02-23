#ifndef UNTRUSTED_ENCLAVE_MESSAGE_EXCHANGE_H_
#define UNTRUSTED_ENCLAVE_MESSAGE_EXCHANGE_H_

#include <stdint.h>
#include "dcap_dh_def.h"
#include "fifo_def.h"
#include "sgx_eid.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t ecdsa_get_qe_target_info_ocall(sgx_target_info_t* qe_target_info);
uint32_t ecdsa_quote_generation_ocall(uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote_buffer);
uint32_t ecdsa_quote_verification_ocall(uint8_t* quote_buffer, uint32_t quote_size);

uint32_t ecdsa_get_qe_target_info_ocall_edl(uint32_t* ret_status, sgx_target_info_t* qe_target_info);
uint32_t ecdsa_quote_generation_ocall_edl(uint32_t* ret_status, uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote_buffer);
uint32_t ecdsa_quote_verification_ocall_edl(uint32_t* ret_status, uint8_t* quote_buffer, uint32_t quote_size);

uint32_t session_request_ocall(sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id, sgx_enclave_id_t target_enclave_id);
uint32_t exchange_report_ocall(sgx_dh_dcap_msg2_t* dh_msg2, sgx_dh_dcap_msg3_t* dh_msg3, uint32_t session_id, sgx_enclave_id_t target_enclave_id);
uint32_t send_request_ocall(uint32_t session_id, void* req_message, size_t req_message_size, size_t max_payload_size, void* resp_message, size_t resp_message_size, sgx_enclave_id_t target_enclave_id);
uint32_t end_session_ocall(uint32_t session_id, sgx_enclave_id_t target_enclave_id);

#ifdef __cplusplus
}
#endif

#endif