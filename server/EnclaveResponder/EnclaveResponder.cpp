// Enclave2.cpp : Defines the exported functions for the DLL application
#include "sgx_eid.h"
#include "EnclaveResponder_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E2.h"
#include "sgx_dh.h"
#include "sgx_utils.h"
#include "common.h"
#include <map>

// #include "ShieldStore/ShieldStore.h"

#define UNUSED(val) (void)(val)

std::map<sgx_enclave_id_t, sgx_dh_dcap_session_t>g_src_session_info_map;

// DCAP identity verification entry point - Gateway version signature
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity, sgx_enclave_id_t wasm_vm_enclave_id)
{
    UNUSED(wasm_vm_enclave_id);
    if (!peer_enclave_identity) return INVALID_PARAMETER_ERROR;

    // check peer enclave's attribute is reasonable: it's INITIALIZED'ed enclave
    if (!(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;

    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
        return ENCLAVE_TRUST_ERROR;
#endif

    return SUCCESS;
}

// Message exchange response generator for DCAP communication
extern "C" uint32_t message_exchange_response_generator(uint8_t *decrypted_data, uint64_t decrypted_data_size, uint64_t max_resp_length, uint8_t *resp_buffer, size_t *resp_length)
{
    // Simple echo implementation for now
    // In a real scenario, this would process the request and generate appropriate response
    if (!decrypted_data || !resp_buffer || !resp_length) {
        return INVALID_PARAMETER_ERROR;
    }

    if (decrypted_data_size > max_resp_length) {
        return OUT_BUFFER_LENGTH_ERROR;
    }

    // Echo the received data back
    memcpy(resp_buffer, decrypted_data, decrypted_data_size);
    *resp_length = decrypted_data_size;

    return SUCCESS;
}
