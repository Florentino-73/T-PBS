// #include "Enclave.h"
#include "ShieldStore.h"
#include "Utility_E2.h"
#include "sgx_tcrypto.h"

/* Global Symmetric Key */
const sgx_ec_key_128bit_t gsk = {
	0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
	0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad
};


/**
 * get all the mac entry for a same hash bucket
 * for integrity verification
 **/
sgx_status_t get_chain_mac(int hash_val,  uint8_t *mac){

	uint8_t temp_mac[HMAC_SIZE];
	uint8_t* aggregate_mac;
	page_entry *pair;
	// budget_entry *pair;

	int count = 0;
	int i;
	int aggregate_mac_idx = 0;
	int index;
	sgx_status_t ret = SGX_SUCCESS;

	memset(temp_mac, 0, HMAC_SIZE);

	/** bucket start index for verifying integrity **/
	int start_index = (int)(hash_val/ratio_root_per_buckets)*ratio_root_per_buckets;

	if(arg_enclave.mac_opt)
	{
		for(index = start_index; index < start_index + ratio_root_per_buckets; index++) {
			count += MACbuf_enclave->entry[index].size;
		}
		aggregate_mac = (uint8_t*)malloc(HMAC_SIZE*count);
		memset(aggregate_mac, 0, HMAC_SIZE*count);

		for(index = start_index; index < start_index + ratio_root_per_buckets; index++) {
			memcpy(aggregate_mac + aggregate_mac_idx, MACbuf_enclave->entry[index].mac, HMAC_SIZE*MACbuf_enclave->entry[index].size);
			aggregate_mac_idx += (HMAC_SIZE*MACbuf_enclave->entry[index].size);
		}
	}
	else
	{
		/* Check chaining size */
		for(index = start_index; index < start_index + ratio_root_per_buckets; index++) {
			pair = ht_enclave->table[index];
			while(pair != NULL){
				count++;
				pair = pair->next;
			}
		}

		//verify
		aggregate_mac = (uint8_t*)malloc(HMAC_SIZE*count);
		memset(aggregate_mac, 0 , HMAC_SIZE*count);

		i = 0;
		for(index = start_index; index < start_index + ratio_root_per_buckets; index++) {
			pair = ht_enclave->table[index];
			while(pair != NULL){
				memcpy(aggregate_mac+(HMAC_SIZE*i), pair->mac, HMAC_SIZE);
				i++;
				pair = pair->next;
			}
		}

	}

	ret = sgx_hmac_sha256_msg(aggregate_mac, HMAC_SIZE*count, (unsigned char *)&gsk, MAC_KEY_SIZE, (unsigned char *)&temp_mac, HMAC_SIZE);
	// ret = sgx_rijndael128_cmac_msg(&gsk, aggregate_mac, HMAC_SIZE * count, &temp_mac);

	if(ret != SGX_SUCCESS)
	{
		// assert(0);
		return ret;
	}
	free(aggregate_mac);

	/* Copy generated MAC to enclave */
	memcpy(mac, (char*)temp_mac, HMAC_SIZE);
	return SGX_SUCCESS;
}


/**
 * verify integrity tree &
 * update integrity tree with updated hash values
 **/
sgx_status_t enclave_rebuild_tree_root(int hash_val, int kv_pos, bool is_insert, uint8_t* prev_mac)
{
	uint8_t temp_mac[HMAC_SIZE];
	uint8_t* aggregate_mac;
	uint8_t* prev_aggregate_mac;
	page_entry *pair;

	int total_mac_count = 0, prev_mac_count = 0, cur_mac_count = 0;
	int aggregate_mac_idx = 0;
	int i, index, updated_idx = -1;
	bool is_cur_idx = false;

	sgx_status_t ret = SGX_SUCCESS;

	memset(temp_mac, 0, HMAC_SIZE);

	/** bucket start index for verifying integrity **/
	int start_index = (int)(hash_val / ratio_root_per_buckets) * ratio_root_per_buckets;

	if (arg_enclave.mac_opt) {
		for (index = start_index; index < start_index + ratio_root_per_buckets; index++) {
			if (index == hash_val) {
				prev_mac_count = total_mac_count;
				/** The location of MAC is the reverse order over the location of key value **/
				if (is_insert)
					updated_idx = prev_mac_count + kv_pos;
				else
					updated_idx = prev_mac_count + (MACbuf_enclave->entry[index].size - kv_pos - 1);
			}
			total_mac_count += MACbuf_enclave->entry[index].size;
		}

		aggregate_mac = (uint8_t *)malloc(HMAC_SIZE * total_mac_count);
		memset(aggregate_mac, 0, HMAC_SIZE * total_mac_count);
		for (index = start_index; index < start_index + ratio_root_per_buckets; index++) {
			memcpy(aggregate_mac + aggregate_mac_idx, MACbuf_enclave->entry[index].mac,
					HMAC_SIZE * MACbuf_enclave->entry[index].size);
			aggregate_mac_idx += (HMAC_SIZE * MACbuf_enclave->entry[index].size);
		}
	}
	else {
		/* Check chaining size */
		for (index = start_index; index < start_index + ratio_root_per_buckets; index++) {
			pair = ht_enclave->table[index];
			is_cur_idx = false;
			if (index == hash_val) {
				prev_mac_count = total_mac_count;
				is_cur_idx = true;
			}
			while (pair != NULL) {
				if (is_cur_idx)
					cur_mac_count++;
				total_mac_count++;
				pair = pair->next;
			}
		}
		if (is_insert)
			updated_idx = prev_mac_count + (cur_mac_count - kv_pos - 1);
		else 
			updated_idx = prev_mac_count + kv_pos;

		//verify
		aggregate_mac = (uint8_t *)malloc(HMAC_SIZE * total_mac_count);
		memset(aggregate_mac, 0 , HMAC_SIZE * total_mac_count);

		i = 0;
		for (index = start_index; index < start_index + ratio_root_per_buckets; index++) {

			pair = ht_enclave->table[index];

			while (pair != NULL) {
				if (pair->mac==NULL) printf("there is a null mac.\n");
				// printf("i: %d. data id:%d. Budget: %d\n",i, pair->data_id, pair->budget);
				// show_ut(pair->mac, MAC_SIZE, "mac is: ");
				memcpy(aggregate_mac+(HMAC_SIZE * i), pair->mac, HMAC_SIZE); // note: MerkleTree --> aggregate (data_id, budget);
				i++;
				pair = pair->next;
			}
		}

	}

	//generate previous mac
	if (is_insert) {
		// assert(kv_pos == 0); // kv_pos must be 0; 
		if (total_mac_count > 1) {
			prev_aggregate_mac = (uint8_t *)malloc(HMAC_SIZE * (total_mac_count - 1));
			memset(prev_aggregate_mac, 0, HMAC_SIZE * (total_mac_count - 1));

			memcpy(prev_aggregate_mac, aggregate_mac, updated_idx * HMAC_SIZE);
			memcpy(prev_aggregate_mac + (updated_idx * HMAC_SIZE),
					aggregate_mac + (updated_idx + 1) * HMAC_SIZE,
					(total_mac_count - updated_idx - 1) * HMAC_SIZE);

			//verify tree root using previous mac
			// ret = sgx_rijndael128_cmac_msg(&gsk, prev_aggregate_mac,
					// HMAC_SIZE * (total_mac_count - 1), &temp_mac);
			ret = sgx_hmac_sha256_msg(prev_aggregate_mac, HMAC_SIZE*(total_mac_count-1), (unsigned char *)&gsk, MAC_KEY_SIZE, (unsigned char *)&temp_mac, HMAC_SIZE);
			free(prev_aggregate_mac);

			if (ret != SGX_SUCCESS)
				return SGX_ERROR_UNEXPECTED;
		}
		else {
			//no need to verify
		}
	}
	else {
		prev_aggregate_mac = (uint8_t *)malloc(HMAC_SIZE * total_mac_count);
		memset(prev_aggregate_mac, 0, HMAC_SIZE * total_mac_count);

		memcpy(prev_aggregate_mac, aggregate_mac, HMAC_SIZE * total_mac_count);
		memcpy(prev_aggregate_mac + updated_idx * HMAC_SIZE, prev_mac, HMAC_SIZE);

		//verify tree root using previous mac
		// ret = sgx_rijndael128_cmac_msg(&gsk, prev_aggregate_mac,
		// 		HMAC_SIZE * total_mac_count, &temp_mac);
		ret = sgx_hmac_sha256_msg(prev_aggregate_mac, HMAC_SIZE*total_mac_count, (unsigned char *)&gsk, MAC_KEY_SIZE, (unsigned char *)&temp_mac, HMAC_SIZE);

		free(prev_aggregate_mac);

		if (ret != SGX_SUCCESS)
			return SGX_ERROR_UNEXPECTED;
	}

	//If ShieldStore stores at least one entry, we can verify tree root
	if (!is_insert || (is_insert && total_mac_count > 1)) {
		if (memcmp(temp_mac, MACTable[hash_val / ratio_root_per_buckets].mac, HMAC_SIZE) != 0) 
		{
			return SGX_ERROR_UNEXPECTED;
		}
	}

	//updated tree root
	// ret = sgx_rijndael128_cmac_msg((sgx_aes_gcm_128bit_key_t*)&gsk, aggregate_mac, HMAC_SIZE * total_mac_count, &temp_mac);

	ret = sgx_hmac_sha256_msg(aggregate_mac, HMAC_SIZE*total_mac_count, (unsigned char *)&gsk, MAC_KEY_SIZE, (unsigned char *)&temp_mac, HMAC_SIZE);


	free(aggregate_mac);
	memcpy(MACTable[hash_val/ratio_root_per_buckets].mac , temp_mac, HMAC_SIZE);

	return ret;
}

/**
 * verify integrity tree
 **/
sgx_status_t enclave_verify_tree_root(int hash_val){

	uint8_t cur_mac[HMAC_SIZE];

	get_chain_mac(hash_val, cur_mac);

	if(memcmp(cur_mac, MACTable[hash_val/ratio_root_per_buckets].mac , HMAC_SIZE) != 0)
		return SGX_ERROR_UNEXPECTED;

	return SGX_SUCCESS;
}



sgx_status_t enclave_cal_mac(uint32_t pid, uint32_t *budgets, uint8_t *nac, uint8_t *mac, const sgx_cmac_128bit_key_t *kdk){
	uint8_t* tmp_plaintext;
	uint8_t tmp_nac[NAC_SIZE];
	// sgx_cmac_128bit_tag_t tmp_mac;
	uint8_t tmp_mac[HMAC_SIZE];
	memcpy(tmp_nac, nac, NAC_SIZE);

	tmp_plaintext = (uint8_t *)malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE+NAC_SIZE+sizeof(uint32_t));
	memcpy(tmp_plaintext, &pid, sizeof(uint32_t));
	memcpy(tmp_plaintext+sizeof(uint32_t), tmp_nac, NAC_SIZE);
	memcpy(tmp_plaintext+sizeof(uint32_t)+NAC_SIZE, budgets, ENTRY_PAGE_SIZE*sizeof(uint32_t));

	// sgx_status_t ret = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *)kdk, tmp_plaintext, sizeof(uint32_t)*ENTRY_PAGE_SIZE+NAC_SIZE+sizeof(uint32_t), &tmp_mac); 
	// sgx_status_t ret = sgx_rijndael128_cmac_msg((sgx_aes_gcm_128bit_key_t*)&gsk, tmp_plaintext, sizeof(uint32_t)*ENTRY_PAGE_SIZE+NAC_SIZE+sizeof(uint32_t), &tmp_mac); 

	sgx_status_t ret = sgx_hmac_sha256_msg(tmp_plaintext, sizeof(uint32_t)*ENTRY_PAGE_SIZE+NAC_SIZE+sizeof(uint32_t), (unsigned char *)&gsk, MAC_KEY_SIZE, (unsigned char *)&tmp_mac, HMAC_SIZE);

	if (ret!=SGX_SUCCESS) {
		return ret;
	}

	memcpy(mac, tmp_mac, HMAC_SIZE);
	SAFE_FREE(tmp_plaintext);

	return SGX_SUCCESS;
}


sgx_status_t enclave_verify_mac_(uint32_t pid, uint32_t *budgets, uint8_t* nac, uint8_t *mac, const sgx_cmac_128bit_key_t *kdk){
	if (kdk == NULL){
	}

	uint8_t* tmp_plaintext;
	// sgx_cmac_128bit_tag_t tmp_mac;
	uint8_t tmp_mac[HMAC_SIZE];
	uint8_t tmp_nac[NAC_SIZE];

	memcpy(tmp_nac, nac, NAC_SIZE);
	memset(tmp_mac, 0, HMAC_SIZE);

	tmp_plaintext = (uint8_t *)malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE+NAC_SIZE+sizeof(uint32_t));
	memcpy(tmp_plaintext, &pid, sizeof(uint32_t));
	memcpy(tmp_plaintext+sizeof(uint32_t), tmp_nac, NAC_SIZE);
	memcpy(tmp_plaintext+sizeof(uint32_t)+NAC_SIZE, budgets, ENTRY_PAGE_SIZE*sizeof(uint32_t));

	// sgx_status_t ret = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *)kdk, tmp_plaintext, sizeof(uint32_t)*2 + NAC_SIZE, &tmp_mac); 
	// sgx_status_t ret = sgx_rijndael128_cmac_msg((sgx_aes_gcm_128bit_key_t*)&gsk, tmp_plaintext, sizeof(uint32_t)*ENTRY_PAGE_SIZE+NAC_SIZE+sizeof(uint32_t), &tmp_mac); 

	sgx_status_t ret = sgx_hmac_sha256_msg(tmp_plaintext, sizeof(uint32_t)*ENTRY_PAGE_SIZE+NAC_SIZE+sizeof(uint32_t), (unsigned char *)&gsk, MAC_KEY_SIZE, (unsigned char*)&tmp_mac, HMAC_SIZE);


/* 	printf("sgx calculate cmc succ..\n");
	show_ut(tmp_mac, MAC_SIZE, "calculated veri mac.. ");
	show_ut(mac, MAC_SIZE, "previous mac"); */

	if (memcmp(tmp_mac, mac, HMAC_SIZE) != 0){
		return SGX_ERROR_UNEXPECTED;
	}

	SAFE_FREE(tmp_plaintext);
	return SGX_SUCCESS;
}