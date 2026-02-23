#include "KeyGen.h"
#include "uchar_vector.h"
#include "Utility_E2.h"

// typedef std::vector<unsigned char> bytes_t;
typedef unsigned int uint32_t; 

// const Ipp8u CURVE_ORDER_BYTES[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const Ipp8u CURVE_ORDER_BYTES[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xfe,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

// Init CURVE ORDER;
BigInt CURVE_ORDER((sizeof(CURVE_ORDER_BYTES)-1+3)/sizeof(Ipp32u), CURVE_ORDER_BYTES);

HDKeychain::HDKeychain(){
    valid_ = 0;
    MnemonicCode seed; 
    bytes_t byte_seed;
    byte_seed = seed.toSeed("test-bitcoin", ""); // seed: 64 bytes;
    
    Ipp8u *seed_tmp = (Ipp8u*)malloc(64); 
    std::copy(byte_seed.begin(), byte_seed.end(), seed_tmp); 

    Ipp8u BITCOIN_SEED[] = "426974636f696e2073656564"; // key = "Bitcoin seed"

    Ipp8u res[64];
    ippsHMAC_Message(BITCOIN_SEED, sizeof(BITCOIN_SEED), seed_tmp, 
                byte_seed.size(), res, 64, ippHashAlg_SHA512);

    delete seed_tmp;
    key_.assign(res, res+32);
    chain_code_.assign(res+32, res+64);        
    valid_ = 1;

    // open sgx_context && generate server public key;
    sgx_ecc256_open_context(&key_handle_);
    sgx_ecc256_create_key_pair(&exchange_priv_key_, &exchange_pub_key_, key_handle_);
}

// input: i; output: shared_key;
int HDKeychain::get_dh_key(uint32_t i, sgx_ec256_dh_shared_t *shared_key) const{
    sgx_ec256_private_t priv_key;
    int ret_status;

    ret_status = getChild(i, &priv_key);
    if (ret_status != 0) return ret_status;
    
    ret_status =  sgx_ecc256_compute_shared_dhkey(&priv_key, &exchange_pub_key_, shared_key, key_handle_);
    if (ret_status != 0) return ret_status;
    return 0;
}

// only derive private key;
// return a string;
int HDKeychain::getChild(uint32_t i, sgx_ec256_private_t *priv_key) const{
    int macLen=64;
    int cS, res;
    uchar_vector data;
    Ipp8u mac[64], chain_code_tmp[32], data_tmp[33+4], key_tmp[33];
    
    if(!valid_) return 1;
    
    data += key_; // key_: 33 bytes;
    data.push_back(i>>24);
    data.push_back((i >> 16) & 0xff);
    data.push_back((i >> 8) & 0xff);
    data.push_back(i & 0xff); // i: 32 bits; 

    // calculate sha 512 using chain_code_ | data;
    // data = data = prv_key | i ; key = chain_code_; output = mac; algo = sha512;
    data.copyToArray(data_tmp);
    std::copy(chain_code_.begin(),chain_code_.end(), chain_code_tmp); 

    ippsHMAC_Message(data_tmp, data.size(), chain_code_tmp, chain_code_.size(), mac, macLen, ippHashAlg_SHA512);

    BigInt I_left(8, mac);
   
    // BigNum calculation;
    Ipp32u tmp_res;
    ippsCmp_BN(CURVE_ORDER.BN_, I_left.BN_, &tmp_res);
    if (tmp_res != 1){
        // printf("COMPARE ERROR! TMP RES IS: %d\n\n\n", tmp_res);
        return 1;
    }

    // is private;
    // k = key_; k += I_left; k %= CURVE_ORDER; 
    std::copy(key_.begin(),key_.end(), key_tmp);
    BigInt k(key_.size()/sizeof(Ipp32u), key_tmp); 

    int size_sum, size_sum_context, res_length;
    IppsBigNumState* SUM;
    

    size_sum = IPP_MAX(sizeof(k.BN_), sizeof(I_left.BN_)); // size_sum = 8;
    ippsBigNumGetSize(size_sum+1, &size_sum_context);

    // init SUM;
    SUM = (IppsBigNumState*)malloc(size_sum_context); // sizeNUM: cS;
    ippsBigNumInit(size_sum + 1, SUM);
    // operation
    ippsAdd_BN(k.BN_, I_left.BN_, SUM);

    res_length  = (size_sum + 1)*4;
    Ipp8u *child;
    child = (Ipp8u*)malloc(res_length);
    // *child = new Ipp8u[res_length]; 
    ippsGetOctString_BN(child, res_length, SUM);
    ippsMod_BN(SUM, CURVE_ORDER.BN_, SUM);

    // init res; 
    res_length  = (size_sum )*4;
    ippsGetOctString_BN(child, res_length, SUM);

    memcpy(priv_key, child, SGX_ECP256_KEY_SIZE);

    delete SUM;    
    delete child;
    return 0;
}