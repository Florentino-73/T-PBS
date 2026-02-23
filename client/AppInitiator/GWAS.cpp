#include "GWAS.h"
#include "fifo_def.h"
#include <iomanip>
#include <glog/logging.h>
#include "EnclaveExecutor_u.h"

#include "benchmark.h"

void show_ut(const uint8_t *var, size_t length, const char *fmt){
    (void)var; (void)length; (void)fmt;
}

GWAS_EXECUTOR::GWAS_EXECUTOR(bool _flag){
	flag = _flag;
    sgx_status_t ret; 
    uint32_t ret_status;
    sgx_launch_token_t token = {0}; 
    int update = 0;

	if (flag){
		// note: create gwas and then create gwas session;
		ret = sgx_create_enclave(ENCLAVE_GWAS_NAME, 1, &token, &update, &gwas_enclave_id, NULL);
		if (ret != SGX_SUCCESS){
			printf("failed to load enclave %s, error code is: 0x%x. \n", ENCLAVE_GWAS_NAME, ret);
			throw EXECUTOR_CREATE_ERROR;
		}

		// establish secure connection
		ret = enclave_create_session_with_server(gwas_enclave_id, &ret_status, &session_id);
		if (ret != SGX_SUCCESS || ret_status != 0) {
			printf("failed to establish secure channel(executor): ECALL return 0x%x, error code is 0x%x.\n", ret, ret_status);
			sgx_destroy_enclave(gwas_enclave_id);
			throw ATTESTATION_ERROR;
		}
	}
}


GWAS_EXECUTOR::~GWAS_EXECUTOR(){
	if (flag) {
		sgx_status_t ret;
		uint32_t ret_status;

		ret = ecall_executor_close_session(gwas_enclave_id, &ret_status);
		if (ret != SGX_SUCCESS || ret_status != 0) {
			printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", ret, ret_status);
			sgx_destroy_enclave(gwas_enclave_id);
			throw ATTESTATION_SE_ERROR;
		}    
		sgx_destroy_enclave(gwas_enclave_id);
	}
}


uint32_t GWAS_EXECUTOR::generate_insert_req(uint32_t batch_id, uint32_t data_num, const char *data_content, uint32_t *data_length, unsigned char* resp_add_req){ 
	if (!resp_add_req) return INVALID_PARAMETER;
	add_hash_req *add_req = (add_hash_req *)resp_add_req;

	uint32_t req_size = sizeof(add_hash_req)+data_num*SHA256_DIGEST_LENGTH;
	uint8_t *req_hash = (uint8_t *)malloc(SHA256_DIGEST_LENGTH); 
	if (!req_hash) return MALLOC_ERROR;

	uint32_t start = 0;

	// generate hash;
	for (int i=0; i<data_num; i++){
		SHA256( reinterpret_cast<const unsigned char *>(data_content+start), data_length[i], req_hash);
		start += data_length[i];
		memcpy(add_req->buf+i*SHA256_DIGEST_LENGTH, req_hash, SHA256_DIGEST_LENGTH);
	}

	add_req->batch_id = batch_id;
	add_req->data_num = data_num;
	
	free(req_hash);
	return SUCCESS;
}


// DATA_NUM: num of data content, data_length: length of each data content
uint32_t GWAS_EXECUTOR::insert_hash_req(uint32_t batch_id, uint32_t pid, uint32_t data_num, const char *data_content, uint32_t *data_length){ // wrap shield req body
	SHIELD_REQ_MSG *shield_req_body;
	FIFO_MSG *msg_req, *msg_resp;
	uint32_t req_size;
	size_t resp_size;

	// note: fifo_msg+shield_req_msg+add_hash_req + pid
	req_size = sizeof(FIFO_MSG) + sizeof(SHIELD_REQ_MSG) + sizeof(add_hash_req) + data_num * SHA256_DIGEST_LENGTH + sizeof(uint32_t);
	msg_req = (FIFO_MSG *)malloc(req_size);
	if (!msg_req) return MALLOC_ERROR;

	msg_req ->header.type = FIFO_SHIELD_REQ;
	msg_req->header.size = sizeof(SHIELD_REQ_MSG) + sizeof(add_hash_req) + data_num*SHA256_DIGEST_LENGTH+sizeof(uint32_t);

	shield_req_body = (SHIELD_REQ_MSG *)msg_req->msgbuf;
	shield_req_body->session_id = session_id;
	shield_req_body->type = 4; // type 4: client insert hash
	shield_req_body->size = sizeof(add_hash_req) + data_num*SHA256_DIGEST_LENGTH + sizeof(uint32_t); //note: add_hash_req + pid
	memcpy(shield_req_body->buf, &pid, sizeof(uint32_t));

	uint32_t ret = generate_insert_req(batch_id, data_num, data_content, data_length, shield_req_body->buf+sizeof(uint32_t));
	if (ret != SUCCESS) return ret;

BENCHMARK_START(insert);
	int ioRet = client_send_receive(msg_req, req_size, &msg_resp, &resp_size);
BENCHMARK_STOP(insert);
LOG(WARNING)<<"client request to insert hash, hash num is "<< data_num<<", time: "<<insert.tv_sec<<"::"<<std::setw(9)<<insert.tv_nsec;

	if (ioRet != 0){
		LOG(ERROR)<<"Client send hash insert request error";
		free(msg_req);
		free(msg_resp);
		return INVALID_SESSION;
	}

	if (msg_resp->header.type == FIFO_CLIENT_REJ){
		LOG(INFO)<<"SEND HASH Receiving Rejct...";
		free(msg_resp);
		free(msg_req);
		return SERVER_REJ;
	}else if(msg_resp->header.type == FIFO_CLIENT_ACK){
		LOG(INFO)<<"SEND HASH RECEIVING ACK...";
	}

	free(msg_resp);
	free(msg_req);
	return SUCCESS;
}


uint32_t GWAS_EXECUTOR::generate_key_req(uint32_t batch_id, uint32_t data_num, const char *data_content, uint32_t *data_length, unsigned char *resp_key_req){
	if (!resp_key_req) return INVALID_PARAMETER;

 	get_key_req *key_req = (get_key_req *)resp_key_req;
	uint8_t *req_hash = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
	if (!req_hash) return MALLOC_ERROR;

	key_req->session_id = session_id;
	key_req->batch_id = batch_id;
	key_req->data_num = data_num;
	
	uint32_t start=0;
	for (int i=0; i<data_num; i++){
		SHA256(reinterpret_cast<const unsigned char*>(data_content+start), data_length[i], req_hash);
		start += data_length[i];
		memcpy(key_req->buf+i*SHA256_DIGEST_LENGTH, req_hash, SHA256_DIGEST_LENGTH);
	}
	
	free(req_hash);
	return SUCCESS;
}


uint32_t GWAS_EXECUTOR::get_key(uint32_t batch_id, uint32_t pid, uint32_t data_num, const char *data_content, uint32_t *data_length, char **secure_resp, uint32_t *secure_msg_size){
	SHIELD_REQ_MSG *shield_req_body;
	FIFO_MSG *msg_req, *msg_resp;
	uint32_t req_size;
	size_t resp_size;

	req_size = sizeof(FIFO_MSG) + sizeof(SHIELD_REQ_MSG) + sizeof(get_key_req) + data_num * SHA256_DIGEST_LENGTH + sizeof(uint32_t);
	msg_req = (FIFO_MSG *)malloc(req_size);
	if (!msg_req) return MALLOC_ERROR;

	msg_req ->header.type = FIFO_SHIELD_REQ;
	msg_req->header.size = sizeof(SHIELD_REQ_MSG) + sizeof(get_key_req) + data_num*SHA256_DIGEST_LENGTH+sizeof(uint32_t);

	shield_req_body = (SHIELD_REQ_MSG *)msg_req->msgbuf;
	shield_req_body->session_id = session_id;
	shield_req_body->type = 5; // type 5: executor get key request;
	shield_req_body->size = sizeof(get_key_req) + data_num*SHA256_DIGEST_LENGTH + sizeof(uint32_t);
	memcpy(shield_req_body->buf, &pid, sizeof(uint32_t));

	uint32_t ret = generate_key_req(batch_id, data_num, data_content, data_length, shield_req_body->buf+sizeof(uint32_t));
	if (ret != SUCCESS) return ret; 

BENCHMARK_START(key);
	int io_ret = client_send_receive(msg_req, req_size, &msg_resp, &resp_size);
	if ( io_ret != 0){
		LOG(ERROR)<<"client send key request failed";
		free(msg_req);
		free(msg_resp);
		return INVALID_SESSION;
	}
BENCHMARK_STOP(key);
LOG(WARNING)<<"client req-key request to get , "<<data_num <<" ,key time: "<<key.tv_sec<<"::"<<std::setw(9)<<key.tv_nsec;
		

	if (msg_resp->header.type == FIFO_CLIENT_REJ)
	{
		LOG(ERROR)<<"request key, receiving reject resp.";
		
		uint32_t tmp = 0;
		memcpy(secure_msg_size, &tmp, sizeof(uint32_t));
		*secure_resp = NULL;

		free(msg_resp);
		free(msg_req);
		return SERVER_REJ;
	}
	else if(msg_resp->header.type == FIFO_CLIENT_ACK)
	{
		LOG(INFO)<<"request key receive ack.";

		uint32_t tmp_size = msg_resp->header.size; // tmp size 141
		char* tmp_resp = (char *)malloc(tmp_size);
		if (!tmp_resp) return MALLOC_ERROR;
		
		memcpy(tmp_resp, msg_resp->msgbuf, tmp_size);
		memcpy(secure_msg_size, &tmp_size, sizeof(uint32_t));
		*secure_resp = tmp_resp;

		free(msg_resp);
		free(msg_req);
		return SUCCESS;
	}

	free(msg_resp);
	free(msg_req);
	return SUCCESS;
}


uint32_t GWAS_EXECUTOR::client_update_hash_then_get_key(uint32_t batch_id, uint32_t pid, secure_message_t **encrypted_key, uint32_t *encrypted_key_size){
	char *msg = "HELLO WORLD\0"; // SET MSG;
    uint32_t msg_length = 12;
    uint32_t data_num = 1;

	char *secure_resp;
	uint32_t secure_resp_size;


	uint32_t ret = insert_hash_req(batch_id, pid, data_num, msg, &msg_length);
	if (ret != 0)
	{
		printf("send insert req error, error code 0x%x.\n", ret);
		return ret;
	} 

	ret = get_key(batch_id, pid, data_num, msg, &msg_length, &secure_resp, &secure_resp_size);
	if (ret != 0)
	{
		LOG(ERROR)<<"executor_get key error, code 0x"<<std::hex<<ret;
		return ret;
	}

	*encrypted_key = (secure_message_t *)secure_resp;
	memcpy(encrypted_key_size, &secure_resp_size, sizeof(uint32_t));

	return SUCCESS;
}


uint32_t GWAS_EXECUTOR::add_key(secure_message_t *encrypted_key, uint32_t encrypted_key_size){
	uint32_t ret_status;
	sgx_status_t status = ecall_batch_add_aek(gwas_enclave_id, &ret_status, encrypted_key, encrypted_key_size);
	if (status != SGX_SUCCESS || ret_status != 0) 
	{
		LOG(ERROR)<<"failed to establish secure channel: ECALL return 0x"<<std::hex<<status<<"error code is 0x"<<ret_status;
        // printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
		// sgx_destroy_enclave(gwas_enclave_id);

        return ret_status;
    }
	return SUCCESS;
}


uint32_t GWAS_EXECUTOR::run_gwas(uint32_t id)
{
    char *filename;
    uint32_t file_size, ret_status;
    sgx_status_t status;
    
    get_encrypted_filename(id, &filename);
    FILE *file = fopen(filename, "rb");

    fseek(file, 0, SEEK_END);
    file_size = (uint32_t)ftell(file);
    rewind(file);

    uint8_t *content = (uint8_t *)malloc(file_size);
    if (!content) return MALLOC_ERROR;
    ret_status = fread(content, 1, file_size, file); 
    if (ret_status != file_size) return FILE_ERROR;
    fclose(file);

    status = ecall_run_gwas(gwas_enclave_id, &ret_status, id, content, file_size);
	if (status != SUCCESS)
	{
		LOG(ERROR)<<"open id "<<id<<", sgx status is 0x"<<std::setw(2)<<std::hex<<status<<", ret is 0x"<<std::setw(2)<<ret_status;
    	// printf("open id %d, sgx status is %02x, ret is %02x.\n", id, status, ret_status);
	}

    free(filename);
    free(content);
    return SUCCESS;
}


uint32_t GWAS_EXECUTOR::req_wrapper_and_send(uint32_t page_id, std::vector<uint32_t> &vec_ids, uint32_t req_budget, char **secure_resp, uint32_t *secure_msg_size, uint32_t req_type)
{
	FIFO_MSG *msg_req, *msg_resp;
	uint32_t req_size, data_num;
	size_t resp_size;
	SHIELD_REQ_MSG *shield_req_body;
	proposal_data_batch *proposal;

	data_num = vec_ids.size();
	req_size = sizeof(FIFO_MSG) + sizeof(SHIELD_REQ_MSG) + sizeof(proposal_data_batch) + data_num*ID_SIZE;

	msg_req = (FIFO_MSG *)malloc(req_size);
	if (!msg_req) return MALLOC_ERROR;
	memset(msg_req, 0, req_size);

	msg_req -> header.type = FIFO_SHIELD_REQ;
	msg_req -> header.size = sizeof(SHIELD_REQ_MSG) + sizeof(proposal_data_batch) + data_num*sizeof(uint32_t);

	shield_req_body = (SHIELD_REQ_MSG *)msg_req -> msgbuf;
	shield_req_body->type = req_type; // 2 for normal batch req; 3 for asyn
	shield_req_body->size = sizeof(proposal_data_batch) + data_num*sizeof(uint32_t);

	proposal = (proposal_data_batch *)shield_req_body->buf;
	proposal->data_num = data_num;
	proposal->request_budget = req_budget;
	proposal->page_id = page_id;
	
	for (int i=0; i < data_num; i++)
	{
		memcpy((proposal->buf)+sizeof(uint32_t)*i , &(vec_ids[i]), sizeof(uint32_t));
		// printf("%d, ", vec_ids[i]);
	}

BENCHMARK_START(bgtProposal);
	int ret = client_send_receive(msg_req, req_size, &msg_resp, &resp_size);
BENCHMARK_STOP(bgtProposal);
	if (ret != 0){
		printf("send bgt request error, error code is: %d.\n", ret);
		free(msg_req);
		free(msg_resp);
		return INVALID_SESSION;
	}
LOG(WARNING)<<"Client Budget request data num is: "<<data_num << " , take time: "<<bgtProposal.tv_sec<<"::"<<std::setw(9)<<bgtProposal.tv_nsec;

	if (msg_resp->header.type == FIFO_CLIENT_REJ)
	{
		LOG(ERROR)<<"budget request receive reject";
		
		uint32_t tmp = 0;
		memcpy(secure_msg_size, &tmp, sizeof(uint32_t));
		*secure_resp = NULL;

		free(msg_resp);
		free(msg_req);
		return SERVER_REJ;
	}
	else if(msg_resp->header.type == FIFO_CLIENT_ACK)
	{
		LOG(INFO)<<"budget request receive ack";

		uint32_t tmp_size = msg_resp->header.size; // tmp size 141
		// printf("===============tmp size: %d \n", tmp_size);
		char* tmp_resp = (char *)malloc(tmp_size);
		if (!tmp_resp) return MALLOC_ERROR;

		memcpy(tmp_resp, msg_resp->msgbuf, tmp_size);
		memcpy(secure_msg_size, &tmp_size, sizeof(uint32_t));
		*secure_resp = tmp_resp;

		free(msg_resp);
		free(msg_req);
	}

	return SUCCESS;
}

