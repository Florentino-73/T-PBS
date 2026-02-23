#ifndef __KEYGEN_H__
#define __KEYGEN_H__

#include <vector>
#include "ippcp.h"
#include "sgx_tcrypto.h"
#include <stdlib.h>
#include "mnemoniccode.h"
#include "BigInt.h"

class HDKeychain{
public:
    HDKeychain();
    int getChild(uint32_t i, sgx_ec256_private_t *priv_key) const;
    int get_dh_key(uint32_t i, sgx_ec256_dh_shared_t *shared_key) const;
protected:
    uint32_t child_num_;
    bytes_t chain_code_; // 32 bytes;
    
    bytes_t key_; // 33 bytes; start with 0x00 for private key;
    bytes_t pubkey_; // public key;
    
    sgx_ec256_private_t exchange_priv_key_;
    sgx_ec256_public_t exchange_pub_key_;
    sgx_ecc_state_handle_t key_handle_;

    bool valid_;

    // void updatePubkey();
};

#endif // __KEYGEN_H__