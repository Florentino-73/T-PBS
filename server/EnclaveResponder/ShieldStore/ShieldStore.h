#ifndef ENCLAVE_H_
#define ENCLAVE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <queue>

#include "../EnclaveResponder_t.h"

#include "sgx_trts.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
// #include "sgx_tae_service.h"

#include "gperftools/malloc_hook.h"
#include "gperftools/malloc_extension.h"
#include "gperftools/tcmalloc.h"

#include "datatypes.h"
#include "error_codes.h"
#include "../KeyGen/KeyGen.h"
#include "Utility_E2.h"

#include "sgx_utils.h"
#include "sgx_ecp_types.h"
#include "sgx_tprotected_fs.h"
#include <iostream>
#include <climits>
#include <cassert>

/** Hash related functions; ht_cpp**/
/* void show_entry(budget_entry* entry, const char *prefix); */
int ht_hash(uint32_t key, uint32_t m);
uint8_t key_hash_func(char *key);
page_entry *ht_page_newpair(uint32_t pid, uint32_t *budgets, uint8_t *nac, uint8_t *mac);
uint32_t ht_set(page_entry* updated_entry, uint32_t pid, uint32_t *budgets, uint8_t *nac, uint8_t *mac, int kv_pos);
page_entry* ht_exist(uint32_t pid, int* kv_pos);

/** Security core functions **/
sgx_status_t get_chain_mac(int hash_val,  uint8_t *mac);
//void enclave_rebuild_tree_root(int hash_val);
sgx_status_t enclave_rebuild_tree_root(int hash_val, int kv_pos, bool is_insert, uint8_t* mac);
sgx_status_t enclave_verify_tree_root(int hash_val);
void enclave_encrypt(char* key_val, char *cipher, uint8_t key_idx, uint32_t key_len, uint32_t val_len, uint8_t *nac, uint8_t *mac);

sgx_status_t enclave_cal_mac(uint32_t pid, uint32_t *budgets, uint8_t *nac, uint8_t *mac, const sgx_cmac_128bit_key_t *kdk);
sgx_status_t enclave_verify_mac_(uint32_t pid, uint32_t *budgets, uint8_t* nac, uint8_t *mac, const sgx_cmac_128bit_key_t *kdk);

/** Enclave Shield Handler **/
int store_snp_data(char* inp_buff, uint32_t inp_buff_len, uint32_t data_id, sgx_key_128bit_t kdk);

uint32_t shield_page_insert(uint32_t *budgets, uint32_t pid);
uint32_t shield_page_update(uint32_t *budgets, uint32_t pid);
uint32_t shield_page_get(uint32_t **budgets, uint32_t pid);
// int shield_insert(enc_user_data *user_data, sgx_key_128bit_t kdk);
// int shield_update(proposal_data *proposal, sgx_key_128bit_t kdk);


/** Interface with front-end **/
void enclave_message_pass(void* data);
void enclave_init_values(hashtable* ht_, MACbuffer* MACbuf_, Arg arg);
void ecall_worker_thread(hashtable *ht_, MACbuffer *MACbuf_);


uint32_t request_data(uint32_t data_id, sgx_ec_key_128bit_t *aek);

/* hash table */
extern hashtable *ht_enclave;
/* MAC buffer */
extern MACbuffer *MACbuf_enclave;

extern int ratio_root_per_buckets;

struct _bucketMAC{
	// uint8_t mac[MAC_SIZE];
	uint8_t mac[HMAC_SIZE];
};
typedef _bucketMAC BucketMAC;

extern BucketMAC *MACTable;
extern Arg arg_enclave;

#endif
