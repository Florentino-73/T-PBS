/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "datatypes.h"
#include "sgx_eid.h"
#include "sgx_trts.h"
#include <map>
#include "dcap_dh_def.h"
#include "error_codes.h"

#ifndef LOCALATTESTATION_H_
#define LOCALATTESTATION_H_

// Session information structure (from Gateway)
typedef struct _dh_session_t
{
    uint32_t  session_id; //Identifies the current session
    uint32_t  status; //Indicates session is in progress, active or closed
    union
    {
        struct
        {
			sgx_dh_session_t dh_session;
        }in_progress;

        struct
        {
            sgx_key_128bit_t AEK; //Session Key
            uint32_t counter; //Used to store Message Sequence Number
        }active;
    };
} dh_session_t;

#ifdef __cplusplus
extern "C" {
#endif

// Gateway-style communication functions
ATTESTATION_STATUS create_session(dh_session_t *session_info, sgx_enclave_id_t wasm_vm_enclave_id);
ATTESTATION_STATUS encrypt_to_enclave(dh_session_t *session_info,
                                     uint8_t *inp_buff,
                                     size_t inp_buff_len,
                                     size_t max_out_buff_size,
                                     uint8_t *out_buff,
                                     size_t *out_buff_len,
                                     sgx_enclave_id_t wasm_vm_enclave_id);
ATTESTATION_STATUS close_session(dh_session_t *session_info, sgx_enclave_id_t wasm_vm_enclave_id);
ATTESTATION_STATUS generate_session_id(uint32_t *session_id);

// Note: session_request, exchange_report, end_session are already declared in EDL-generated headers
// DCAP response generator
ATTESTATION_STATUS generate_response(secure_message_t *req_message,
                                   size_t req_message_size,
                                   size_t max_payload_size,
                                   secure_message_t *resp_message,
                                   size_t *resp_message_size,
                                   uint32_t session_id);

uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity, sgx_enclave_id_t wasm_vm_enclave_id);
uint32_t message_exchange_response_generator(uint8_t *decrypted_data, uint64_t decrypted_data_size, uint64_t max_resp_length, uint8_t *resp_buffer, size_t *resp_length);

#ifdef __cplusplus
}
#endif

#endif
