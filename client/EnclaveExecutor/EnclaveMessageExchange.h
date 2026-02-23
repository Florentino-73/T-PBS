
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
uint32_t SGXAPI create_session(dh_session_t *p_session_info);
uint32_t SGXAPI close_session(dh_session_t *p_session_info);

// uint32_t session_decrypt_secure_msg(secure_message_t *resp_data, uint32_t resp_size, char **decrypted_msg, uint32_t *decrypted_length);

#ifdef __cplusplus
}
#endif

#endif
