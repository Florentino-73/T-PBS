// Enclave1.cpp : Defines the exported functions for the .so application
#include <map>
#include <typeinfo>

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "sgx_utils.h"
#include "sgx_error.h"
#include "dh_session_protocol.h"
#include "sgx_tprotected_fs.h"
// #include "openssl/sha.h"

#include "error_codes.h"
#include "Utility_E1.h"
#include "EnclaveInitiator_t.h"
#include "EnclaveMessageExchange.h"

#define UNUSED(val) (void)(val)

#define RESPONDER_PRODID 1

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

dh_session_t g_session;
typedef struct {
    uint32_t rs_id_int;
    uint32_t counters[4];
    uint8_t data[276];
}SNP;

// This is hardcoded responder enclave's MRSIGNER for demonstration purpose. The content aligns to responder enclave's signing key
sgx_measurement_t g_responder_mrsigner = {
	{
		0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14, 0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43,
		0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c, 0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e
	}
};

/* Function Description:
 *   This is ECALL routine to create ECDH session.
 *   When it succeeds to create ECDH session, the session context is saved in g_session.
 * */
extern "C" uint32_t ecall_create_session(uint32_t *session_id){
    uint32_t ret = create_session(&g_session);
    memcpy(session_id, &(g_session.session_id), sizeof(uint32_t));
    return ret;
}


/* Function Description:3
 *   This is ECALL interface to close secure session*/
uint32_t ecall_close_session(){
    ATTESTATION_STATUS ke_status = SUCCESS;
    ke_status = close_session(&g_session);
    //Erase the session context
    memset(&g_session, 0, sizeof(dh_session_t));
    return ke_status;
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
