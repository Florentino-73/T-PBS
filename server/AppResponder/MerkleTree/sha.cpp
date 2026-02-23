#include "sha.h"

void show_hash(hash hash_val){
    (void)hash_val;
}

int compute_hash(const uint8_t *src, uint32_t src_len, hash p_hash){
    SHA256(src, src_len, p_hash);
    return 0;
}

int compute_hash_from_str(const char* str, hash p_hash){
    char *ori_msg = const_cast<char *>(str);
    uint32_t length = strlen(ori_msg);
    const uint8_t* msg = (const uint8_t*)ori_msg;
    return compute_hash(msg, length, p_hash); 
}

int equal_hash(hash p_hash1, hash p_hash2){
    for (int i=0; i<SHA_LEN; i++){
        if (p_hash1[i] != p_hash2[i]){
            return 1;
        }
    }
    return 0;
}


