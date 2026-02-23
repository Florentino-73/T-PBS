#include <map>

#include "sgx_dh.h"
#include "sgx_utils.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_thread.h"
#include "dh_session_protocol.h"

#include "Utility_E1.h"
#include "datatypes.h"
#include "error_codes.h"
#include "../EnclaveInitiator/EnclaveInitiator_t.h"

#ifndef LOCALATTESTATION_H_
#define LOCALATTESTATION_H_

#ifdef __cplusplus
extern "C" {
#endif

uint32_t SGXAPI create_session(dh_session_t *p_session_info);
uint32_t SGXAPI close_session(dh_session_t *p_session_info);

#ifdef __cplusplus
}
#endif

#endif
