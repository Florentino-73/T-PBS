#include "GWAS.h"

uint32_t show_snp_data(SNP_DATA *snp_data, uint32_t elems_num){
    (void)snp_data; (void)elems_num;
    return 0;
}

const uint32_t filename_size = 42;
uint32_t get_encrypted_filename(uint32_t data_id, char **new_filename){
    char *filename = (char *)malloc(filename_size);
    memset(filename, 0, filename_size);
    snprintf(filename, filename_size, "../test_data/gwas_encrypted/%08x.gwas", data_id);
    *new_filename = filename;

    return SUCCESS;
}


int wrap_and_send_user_data(uint32_t session_id, secure_message_t *user_data, size_t user_data_size){
    FIFO_MSG *msgreq = NULL, *msg_resp = NULL;
    SHIELD_REQ_MSG *fifo_user_data;
    size_t req_size, resp_size;
    req_size = sizeof(FIFO_MSG_HEADER) + sizeof(SHIELD_REQ_MSG) + user_data_size;

    msgreq = (FIFO_MSG *)malloc(req_size);
	if (!msgreq) return -1;
	memset(msgreq, 0, req_size);

    msgreq->header.type = FIFO_SHIELD_REQ;
    msgreq->header.size = sizeof(SHIELD_REQ_MSG)+user_data_size;
    fifo_user_data = (SHIELD_REQ_MSG *)msgreq->msgbuf;

	fifo_user_data->session_id = session_id;
	fifo_user_data->size = user_data_size;
    fifo_user_data->type = 0; // send data & store;

	memcpy(fifo_user_data->buf, user_data, user_data_size);

	if(client_send_receive(msgreq, req_size, &msg_resp, &resp_size) != 0){
		free(msgreq);
		printf("Failed send or receive user data.\n");
		return -1;
	}

	if (msg_resp->header.type == FIFO_USER_DATA_ACK){
		free(msg_resp);
		free(msgreq);
		return 0;
	}else if (msg_resp->header.type == FIFO_USER_DATA_REJ){
        free(msg_resp);
		free(msgreq);
		return 0;
    }

    printf("error: resp unknown.\n");

	free(msg_resp);
	free(msgreq);
	return 0;
}


uint32_t process_snp_data(const char* filename, uint32_t budget, enc_user_data **data_capsule, uint32_t *inp_buff_len){
    uint32_t *contents;
    uint32_t user_type, homo_num, heter_num;
    uint32_t file_size, num_elems, elems_read;
    SNP_DATA *snp_data;
    uint32_t size_snp_data, enc_data_len;


    FILE *file = fopen(filename, "rb");
    if (file == NULL){
        printf("Error opening file %s .\n", filename);
        return -1;
    }
    fseek(file, 0, SEEK_END); // move file pointer to the end
    file_size = (uint32_t) ftell(file);
    rewind(file); // move to begin

    num_elems = file_size / sizeof(uint32_t);  // number + ids;
    contents = (uint32_t*) malloc(sizeof(uint32_t)*num_elems); 
    if(contents == NULL ) return MALLOC_ERROR;
    
    elems_read = fread(contents, sizeof(uint32_t), num_elems, file);
    if (elems_read != num_elems) return ERROR_TAG_MISMATCH;
    fclose(file);
    
    user_type = contents[0];
    homo_num = contents[1]; // note: bin file store homo first, then heter;
    heter_num = num_elems - 2 - homo_num;
    
    /* set snp data begin */
    size_snp_data = sizeof(SNP_DATA) + (num_elems-2)*sizeof(uint32_t);
    enc_data_len = sizeof(enc_user_data) + size_snp_data;

    *data_capsule = (enc_user_data *)malloc(enc_data_len);
    snp_data = (SNP_DATA*)((*data_capsule)->enc_data);

    if (*data_capsule == NULL || snp_data == NULL){
        printf("ERROR: malloc failed...\n");
        return -1;
    }
    
    if (user_type == 0){ // control
        snp_data->user_type = 0;
    }else{ // case 
        snp_data->user_type = 1;
    }
    snp_data -> homo_num = homo_num;

    memcpy(snp_data->SNPs, contents+2, (num_elems-2)*sizeof(uint32_t));
    free(contents);
    /* set snp data end */

    // show_snp_data(snp_data, num_elems-2);

    /* Begin: Wrap SNP_DATA to enc_user_data */ 
    (*data_capsule)->data_id = 0; // note: place holder;
    (*data_capsule)->budget = budget;
    (*data_capsule)->data_len = size_snp_data;
    memcpy(inp_buff_len, &enc_data_len, sizeof(uint32_t));

    return 0;

}


uint32_t gwas_req_data(uint32_t session_id, uint32_t data_id, uint32_t request_budget, secure_message_t *resp_data){
	FIFO_MSG *msg_req = NULL, *msg_resp = NULL;
	SHIELD_REQ_MSG *msg_body;
	size_t req_size, resp_size;
	proposal_data *proposal;

	if (!resp_data){
		printf("error! no resp_data for receiving..\n ");
		return ERROR_OUT_OF_MEMORY;
	}

	// set msg header;
	req_size = sizeof(FIFO_MSG) + sizeof(SHIELD_REQ_MSG) + sizeof(proposal_data);

	msg_req = (FIFO_MSG *)malloc(req_size);
	if (!msg_req) return ERROR_OUT_OF_MEMORY;
	memset(msg_req, 0, req_size);

	msg_req -> header.type = FIFO_SHIELD_REQ;
	msg_req -> header.size = sizeof(SHIELD_REQ_MSG) + sizeof(proposal_data);

	// set request info;
	msg_body = (SHIELD_REQ_MSG *)msg_req -> msgbuf;
	msg_body -> session_id = session_id;
	msg_body -> type = 1; // request data, send proposal data.

	proposal = (proposal_data *)msg_body -> buf;
	proposal->data_id = data_id;
	proposal->request_budget = request_budget;
	// proposal->session_id = session_id;
	

	if (client_send_receive(msg_req, req_size, &msg_resp, &resp_size) != 0){
		free(msg_req);
		printf("FAILED TO SEND CLIENT DATA REQUEST.\n");
		return INVALID_SESSION;
	}
	
	if (msg_resp->header.type == FIFO_CLIENT_REJ){
		free(msg_req);
		free(msg_resp);
		return INVALID_PARAMETER;
		
	}else if (msg_resp->header.type == FIFO_CLIENT_ACK){ 
		return (ATTESTATION_STATUS)0;
		memcpy(resp_data, msg_resp->msgbuf, sizeof(secure_message_t)+sizeof(proposal_data));  
	}else{
		printf("unkown resp for requesting data %d.\n", data_id);
		return INVALID_SESSION;
	}

	free(msg_req);
	free(msg_resp);
	return (ATTESTATION_STATUS)0;
}


uint32_t gen_file_req_header(uint32_t session_id, FIFO_MSG **request_msg, size_t *request_size){
    FIFO_MSG *msgreq = NULL, *msg_resp = NULL;
    SHIELD_REQ_MSG *fifo_user_data;
    size_t req_size, resp_size;
    uint32_t ret_status;
    
    // gen user request --> send
    req_size = sizeof(FIFO_MSG_HEADER) + sizeof(SHIELD_REQ_MSG);
    msgreq = (FIFO_MSG*)malloc(req_size);
    if (!msgreq) return MALLOC_ERROR; 
    memset(msgreq, 0, req_size);

    msgreq->header.type = FIFO_SHIELD_REQ;
    msgreq->header.size = sizeof(SHIELD_REQ_MSG);
    SHIELD_REQ_MSG *fifo_user_req = (SHIELD_REQ_MSG*)msgreq->msgbuf;

    fifo_user_req->session_id = session_id;
    fifo_user_req->size = 0;
    fifo_user_req->type = 6;

    *request_msg = msgreq;
    memcpy(request_size, &req_size, sizeof(size_t));

    return SUCCESS;
}


