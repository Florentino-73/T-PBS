#ifndef HASH_HPP
#define HASH_HPP
#include <sgx_tcrypto.h>  // sha256
#include <cstdlib> // malloc
#include <string.h> // strelen
#include <stdint.h> // uint32_t
typedef sgx_sha256_hash_t hash;
#define SHA_LEN 32

int compute_hash(const uint8_t *src, uint32_t src_len, hash *p_hash);
int compute_hash_from_str(const char* str, hash *p_hash);
int equal_hash(hash *p_hash1, hash *p_hash2);
int validate_hash(const uint8_t *src, uint32_t src_len, hash *p_hash);
int compute_hash_from_budget(const uint32_t budget, hash *p_hash);

#endif
