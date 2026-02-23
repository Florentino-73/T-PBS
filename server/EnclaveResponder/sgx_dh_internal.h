/*
 * SGX DH Internal structures for Server EnclaveResponder
 */

#ifndef _SGX_DH_INTERNAL_H_
#define _SGX_DH_INTERNAL_H_

#include "tdcap_dh.h"

#pragma pack(push, 1)
 
typedef enum _sgx_dh_session_state_t
{
    SGX_DH_SESSION_STATE_ERROR,
    SGX_DH_SESSION_STATE_RESET,
    SGX_DH_SESSION_RESPONDER_WAIT_M2,
    SGX_DH_SESSION_INITIATOR_WAIT_M1,
    SGX_DH_SESSION_INITIATOR_WAIT_M3,
    SGX_DH_SESSION_ACTIVE
} sgx_dh_session_state_t;

typedef struct _sgx_dh_responder_t{
    sgx_dh_session_state_t   state;	   /*Responder State Machine State */
    sgx_ec256_private_t prv_key;             /* 256bit EC private key */
    sgx_ec256_public_t  pub_key;             /* 512 bit EC public key */
} sgx_dh_responder_t;
 
typedef struct _sgx_dh_initator_t{
    sgx_dh_session_state_t state;    /* Initiator State Machine State */
    union{
        sgx_ec256_private_t prv_key;    /* 256bit EC private key */
        sgx_key_128bit_t smk_aek;    /* 128bit SMK or AEK. Depending on the State */
    };
    sgx_ec256_public_t pub_key;    /* 512 bit EC public key */
    sgx_ec256_public_t peer_pub_key;    /* 512 bit EC public key from the Responder */
    sgx_ec256_dh_shared_t shared_key;
} sgx_dh_initator_t;

typedef struct _sgx_internal_dh_session_t{
    sgx_dh_session_role_t role;             /* Initiator or Responder */
    union{
        sgx_dh_responder_t responder;
        sgx_dh_initator_t  initiator;
    };
} sgx_internal_dh_session_t;

#define se_static_assert(e) static_assert(e, "static assert error")
se_static_assert(sizeof(sgx_internal_dh_session_t) == SGX_DH_SESSION_DATA_SIZE); /*size mismatch on sgx_internal_dh_session_t and sgx_dh_session_t*/

#pragma pack(pop)

#endif
