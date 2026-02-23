#ifndef _ECDSA_OCALLS_H_
#define _ECDSA_OCALLS_H_

#include "sgx_report.h"
#include "sgx_qe_header.h"

#ifdef __cplusplus
extern "C" {
#endif

// ECDSA DCAP OCALL function declarations
uint32_t ecdsa_get_qe_target_info_ocall(sgx_target_info_t* qe_target_info);
uint32_t ecdsa_quote_generation_ocall(uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote_buffer);
uint32_t ecdsa_quote_verification_ocall(uint8_t* quote_buffer, uint32_t quote_size);

#ifdef __cplusplus
}
#endif

#endif // _ECDSA_OCALLS_H_