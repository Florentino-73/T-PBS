/*
 * ECP interface for Server EnclaveResponder
 */

#ifndef _ECP_INTERFACE_H
#define _ECP_INTERFACE_H

#include "sgx_ecp_types.h"
#include "sgx_tcrypto.h"

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
const uint16_t AES_CMAC_KDF_ID = 0x0001;

sgx_status_t app_derive_key(
    const sgx_ec256_dh_shared_t* shared_key,
    const char* label,
    uint32_t label_length,
    sgx_ec_key_128bit_t* derived_key);

#ifndef INTERNAL_SGX_ERROR_CODE_CONVERTOR
#define INTERNAL_SGX_ERROR_CODE_CONVERTOR(x) if(x != SGX_ERROR_OUT_OF_MEMORY){x = SGX_ERROR_UNEXPECTED;}
#endif

#endif
