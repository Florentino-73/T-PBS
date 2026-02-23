#include "sha.h"

int compute_hash(const uint8_t *src, uint32_t src_len, hash *p_hash){
    sgx_status_t ret;
    ret = sgx_sha256_msg(src, src_len, p_hash);
    if ( ret != SGX_SUCCESS){
        return 1;
    }
    return 0;
}

int compute_hash_from_str(const char* str, hash *p_hash){
    char *ori_msg = const_cast<char *>(str);
    size_t length = strlen(ori_msg);
    const uint8_t* msg = (const uint8_t*)ori_msg;
    return compute_hash(msg, length, p_hash); 
}

int validate_hash(const uint8_t *src, uint32_t src_len, hash *p_hash){
    hash *new_hash = (hash *)malloc(SHA_LEN);
    compute_hash(src, src_len, new_hash);
    if (equal_hash(new_hash, p_hash)){
        delete new_hash;
        return 1;
    }else{
        delete new_hash;
        return 0;
    }

}

int compute_hash_from_budget(const uint32_t budget, hash *p_hash){
    uint8_t *tmp_budget;
    tmp_budget = (uint8_t*)malloc(sizeof(uint32_t));
    memcpy(tmp_budget, &budget, sizeof(uint32_t));

    int ret = compute_hash(tmp_budget, sizeof(uint32_t), p_hash);
    delete tmp_budget;
    return ret;
}

int equal_hash(hash *p_hash1, hash *p_hash2){
    for (int i=0; i<SHA_LEN; i++){
        if ((*p_hash1)[i] != (*p_hash2)[i]){
            return 1;
        }
    }
    return 0;
}
