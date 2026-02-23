#include "sgx.h"
#include "sgx_defs.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"

#ifndef _DCAP_DH_DEF_H_
#define _DCAP_DH_DEF_H_

#pragma pack(push, 1)

#define SGX_DH_MAC_SIZE 16
#define SGX_DH_SESSION_DATA_SIZE 200
#define SGX_QUOTE3_BUFFER_SIZE 5000

typedef struct _sgx_dh_dcap_msg1_t
{
    sgx_ec256_public_t  g_a;     /* the Endian-ness of Ga is Little-Endian */
} sgx_dh_dcap_msg1_t;

typedef struct _sgx_dh_dcap_msg2_t
{
    sgx_ec256_public_t  g_b;     /* the Endian-ness of Gb is Little-Endian */
} sgx_dh_dcap_msg2_t;

typedef struct _sgx_dh_dcap_msg3_body_t
{
    uint32_t     quote_size;
    uint8_t quote_buffer[SGX_QUOTE3_BUFFER_SIZE];
} sgx_dh_dcap_msg3_body_t;

typedef struct _sgx_dh_dcap_msg3_t
{
    uint8_t            cmac[SGX_DH_MAC_SIZE];
    sgx_dh_dcap_msg3_body_t msg3_body;
} sgx_dh_dcap_msg3_t;

// Use existing SGX SDK types instead of redefining:
// - sgx_dh_session_enclave_identity_t (already defined in sgx_dh.h)
// - sgx_dh_session_role_t (already defined in sgx_dh.h)  
// - sgx_dh_session_t (already defined in sgx_dh.h)

#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
