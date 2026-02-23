#include <map>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <glog/logging.h>
#include "openssl/sha.h"

#include "fifo_def.h"
#include "datatypes.h"
#include "error_codes.h"
#include "EnclaveInitiator_u.h"

#ifndef APPINIT_H_
#define APPINIT_H_


uint32_t split_ids(uint32_t data_num, uint32_t *data_ids, std::map<uint32_t, std::vector<uint32_t>* > &page_map);
// uint32_t req_wrapper_and_send(uint32_t page_id, std::vector<uint32_t> &vec_ids, uint32_t session_id, uint32_t req_budget, char **secure_resp, uint32_t *secure_msg_size, uint32_t req_type);
uint32_t get_file_req(uint32_t id);
uint32_t client_req_asyn_data(uint32_t max_data_id=100000, uint32_t data_num=1000, bool GWAS=false);

#endif