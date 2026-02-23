// #include "Enclave.h"
#include "ShieldStore.h"

uint8_t key_hash_func(char *key){
	unsigned long int hashval = 7;
	int i = 0;
	/* Convert our string to an integer */
	while(hashval < ULONG_MAX && i < strlen(key)){
		hashval = hashval*11;
		hashval += key[i];
		i++;
	}

	return hashval % 256; //int8_t can store 0 ~ 255
}


/* Hash a string for a particular hash table. */
int ht_hash(uint32_t key, uint32_t m){ 
	key = (key + 0x7ed55d16) + (key << 12);
	key = (key ^ 0xc761c23c) ^ (key >> 19);
	key = (key + 0x165667b1) + (key << 5);
	key = (key + 0xd3a2646c) ^ (key << 9);
	key = (key + 0xfd7046c5) + (key << 3);
	key = (key ^ 0xb55a4f09) ^ (key >> 16);
	return key % m;
}


page_entry *ht_page_newpair(uint32_t pid, uint32_t* budgets, uint8_t *nac, uint8_t *mac){
	page_entry *newpair;

	// if ((budgets=(uint32_t*)ocall_tc_malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE))==NULL) return NULL;

	if ((newpair = (page_entry*)ocall_tc_malloc(sizeof(page_entry)))==NULL) return NULL;

	if (memcpy(newpair->mac, mac, HMAC_SIZE) == NULL) return NULL;
	if (memcpy(newpair->nac, nac, NAC_SIZE) == NULL) return NULL;

	newpair->pid = pid;
	newpair->budgets = budgets;
	newpair->next = NULL;

	return newpair;
}


page_entry* ht_exist(uint32_t pid, int* kv_pos){
	int bin=0;
	page_entry *pair; 
	*kv_pos = 0;

	bin = ht_hash(pid, arg_enclave.num_threads);
	pair = ht_enclave->table[bin];

	while (pair != NULL)
	{
		if (pair->pid == pid){
			assert(sgx_is_outside_enclave(pair, sizeof(*pair)));
			// assert(sgx_is_outside_enclave(pair->data, pair->val_size ));
			return pair;
		}
		pair = pair->next;
		(*kv_pos)++;
	}
	return NULL;	
}


uint32_t ht_set(page_entry* updated_entry, uint32_t pid, uint32_t *budgets, uint8_t *nac, uint8_t *mac, int kv_pos){

	int bin = ht_hash(pid, arg_enclave.num_threads);
	int pos=-1;
	page_entry *newpair = NULL;

	// update 
	if (updated_entry != NULL){
		updated_entry->budgets = budgets;
		memcpy(updated_entry->nac, nac, NAC_SIZE);
		memcpy(updated_entry->mac, mac, HMAC_SIZE);

		if (arg_enclave.mac_opt){
			pos = MACbuf_enclave->entry[bin].size - kv_pos - 1;
			memcpy(MACbuf_enclave->entry[bin].mac+ (HMAC_SIZE*pos), mac, HMAC_SIZE);
		}

	}else{ // insert; 
		newpair = ht_page_newpair(pid, budgets, nac, mac);
		if (!newpair){
			return -1;
		} 
		// show_entry(newpair, "new pair with contents:");
		if (updated_entry == ht_enclave->table[bin]){
			newpair->next = NULL;
			ht_enclave->table[bin] = newpair;
		}else if (!updated_entry){
			newpair->next = ht_enclave->table[bin];
			ht_enclave->table[bin] = newpair;
		}

		if (arg_enclave.mac_opt){
			MACbuf_enclave->entry[bin].size ++;
			memcpy(MACbuf_enclave->entry[bin].mac + HMAC_SIZE*kv_pos, mac, HMAC_SIZE);
		}
	}

	// show_entry(updated_entry, "In set, insert;");
	return 0;
}


/* void show_entry(budget_entry* entry, const char *prefix){
	show_ut(entry->mac, MAC_SIZE, "\t\tmac:");
	// show_ut(entry->nac, NAC_SIZE, "\t\tnac:");
} */