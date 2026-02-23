#ifndef HASH_HPP
#define HASH_HPP

#include <openssl/sha.h>
#include <cstdlib> // malloc
#include <string.h> // strelen
#include <stdint.h> // uint32_t
#include <stdio.h>

typedef uint8_t* hash;
#define SHA_LEN SHA256_DIGEST_LENGTH

void show_hash(hash hash_val);
int compute_hash(const uint8_t *src, uint32_t src_len, hash p_hash);
int compute_hash_from_str(const char* str, hash p_hash);
int equal_hash(hash p_hash1, hash p_hash2);

#endif
