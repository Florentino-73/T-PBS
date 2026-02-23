#include "ShieldStore.h"
#include "../Utility_E2.h"
// #include "sgx_error.h"

// HDKeychain DH_Seed;

#ifndef ERROR_BREAK
#define ERROR_BREAK(x)  if(x != ippStsNoErr){break;}
#endif
#ifndef NULL_BREAK
#define NULL_BREAK(x)   if(!x){break;}
#endif
#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

#define MAC_KEY_SIZE       16

/* Global Symmetric Key */
const sgx_ec_key_128bit_t gsk = {
	0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
	0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad
};

// #define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)




int store_snp_data(char* inp_buff, uint32_t inp_buff_len, uint32_t data_id, sgx_key_128bit_t kdk){
    size_t f_res;
    uint32_t elems_num = (inp_buff_len - sizeof(SNP_DATA)) / sizeof(uint32_t);
    SNP_DATA *snp_data = (SNP_DATA*)inp_buff;
    
    if (kdk == NULL){
        return -1;
    }

    /* BEGIN: file storage */
    char *filename = (char *)malloc(FILENAME_SIZE);
    memset(filename, 0, FILENAME_SIZE);
    snprintf(filename, FILENAME_SIZE-1, "%08x.txt", data_id);

    SGX_FILE *snp_file;  

    snp_file = sgx_fopen(filename, "w", (sgx_key_128bit_t *)&kdk);
    if (NULL == snp_file) return INVALID_ARGUMENT;

    uint32_t snp_nums = (inp_buff_len - sizeof(SNP_DATA)) / sizeof(uint32_t) ;
    if (snp_nums * sizeof(uint32_t) != inp_buff_len-sizeof(SNP_DATA)){
        return -1;
    }

    // show_snp_data(snp_data, snp_nums);

    // note: only store homo_num
    sgx_fwrite(&(snp_data->user_type), sizeof(uint8_t), 1, snp_file);
    sgx_fwrite(&(snp_data->homo_num), sizeof(uint32_t), 1, snp_file);
    f_res = sgx_fwrite(snp_data->SNPs, sizeof(uint32_t), snp_nums, snp_file);

    if (f_res != snp_nums){
        return -1;
    }
    
    f_res = sgx_fclose(snp_file);

    if (f_res != 0){
        return INVALID_ARGUMENT;
    }
    /* END: file storage */
    SAFE_FREE(filename);
    return 0;
}


uint32_t shield_page_insert(uint32_t *budgets, uint32_t pid){ // new page
    uint8_t nac[NAC_SIZE];
    uint8_t mac[HMAC_SIZE];
    uint8_t prev_mac[HMAC_SIZE];
    uint8_t updated_nac[NAC_SIZE];
    int kv_pos = -1;

    memset(nac, 0, NAC_SIZE);
    memset(mac, 0, HMAC_SIZE);

    page_entry *ret_entry = ht_exist(pid, &kv_pos);
    if (ret_entry != NULL)
    {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    if (sgx_read_rand(nac, NAC_SIZE)!= SGX_SUCCESS)
    {
        return MALLOC_ERROR;
    }
    sgx_status_t status = enclave_cal_mac(pid, budgets, nac, mac, &gsk);
    if (SGX_SUCCESS != status)
    {
        return -1;
    }

    int ret = ht_set(ret_entry, pid, budgets, nac, mac, kv_pos);
    if (ret != 0){
        return ERROR_UNEXPECTED;
    }

    int hash_val = ht_hash(pid, arg_enclave.num_threads);
    status = enclave_rebuild_tree_root(hash_val, kv_pos, 1, NULL);
    if (status!= SGX_SUCCESS)
    {
        return ERROR_UNEXPECTED;
    }

    return SUCCESS;
}


uint32_t shield_page_update(uint32_t *budgets, uint32_t pid){
    uint8_t nac[NAC_SIZE];
    uint8_t mac[HMAC_SIZE];
    uint8_t prev_mac[HMAC_SIZE];
    uint8_t updated_nac[NAC_SIZE];
    int kv_pos = -1; 

    page_entry *ret_entry = ht_exist(pid, &kv_pos);
    if (ret_entry == NULL)
    {
        return INVALID_PARAMETER;
    }

    sgx_status_t ret = enclave_verify_mac_(ret_entry->pid, ret_entry->budgets, ret_entry->nac, ret_entry->mac, &gsk);

    if (ret != SGX_SUCCESS){
        return INVALID_PARAMETER;
    }

    if (ret_entry->budgets != budgets)
    {
        ocall_tc_free(ret_entry->budgets); 
    }

    memcpy(prev_mac, ret_entry->mac, HMAC_SIZE);
    sgx_read_rand(updated_nac, NAC_SIZE);
    enclave_cal_mac(pid, budgets, updated_nac, mac, &gsk);

    ht_set(ret_entry, pid, budgets, updated_nac, mac, kv_pos);

    int hash_val = ht_hash(pid, arg_enclave.num_threads);
    ret = enclave_rebuild_tree_root(hash_val, kv_pos, 0, prev_mac);

    if (ret!= SGX_SUCCESS)
    {
        return INVALID_PARAMETER;
    }
    return SUCCESS;
}


uint32_t shield_page_get(uint32_t **budgets, uint32_t pid)
{
    int kv_pos = -1; 

    page_entry *ret_entry = ht_exist(pid, &kv_pos);
    if (ret_entry == NULL)
    {
        *budgets = NULL;
        return SUCCESS;
    }

    sgx_status_t ret = enclave_verify_mac_(ret_entry->pid, ret_entry->budgets, ret_entry->nac, ret_entry->mac, &gsk);
    if (ret != SGX_SUCCESS){
        return INVALID_PARAMETER;
    }

    *budgets = ret_entry->budgets;
    return SUCCESS;
}



uint32_t request_data(uint32_t data_id, sgx_ec_key_128bit_t *aek){
    (void)data_id;
    (void)aek;
    return SUCCESS;
}

