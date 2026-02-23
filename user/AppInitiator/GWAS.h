
#include <map>
#include <ctime>
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <sched.h>
#include <sys/sysinfo.h>

#include "omp.h"

#include "sgx_eid.h"
#include "sgx_urts.h"


#include "datatypes.h"
#include "fifo_def.h"
#include "UntrustedEnclaveMessageExchange.h"


#ifndef __GWAS_H__
#define __GWAS_H__

uint32_t get_encrypted_filename(uint32_t data_id, char **new_filename);

uint32_t gen_file_req_header(uint32_t session_id, FIFO_MSG **request_msg, size_t *request_size);
uint32_t show_snp_data(SNP_DATA *snp_data, uint32_t elems_num);

int wrap_and_send_user_data(uint32_t session_id, secure_message_t *user_data, size_t user_data_size);
uint32_t gwas_req_data(uint32_t session_id, uint32_t data_id, uint32_t request_budget, secure_message_t *resp_data);
uint32_t process_snp_data(const char* filename, uint32_t budget, enc_user_data **data_capsule, uint32_t *inp_buff_len);

#endif