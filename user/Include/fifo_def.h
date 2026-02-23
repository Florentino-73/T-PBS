#ifndef _FIFO_DEF_H_
#define _FIFO_DEF_H_

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "dcap_dh_def.h"  // Include DCAP definitions

// NOTE: the fifo_msg_type must be the same between client and server
typedef enum{
	FIFO_DH_REQ_MSG1,
	FIFO_DH_RESP_MSG1,
	FIFO_DH_MSG2,
	FIFO_DH_MSG3,
	FIFO_DH_MSG_REQ,
	FIFO_DH_MSG_RESP,
	FIFO_DH_CLOSE_REQ,
	FIFO_DH_CLOSE_RESP,
	FIFO_CLIENT_REQ,
	FIFO_CLIENT_ACK,
	FIFO_USER_REQ,
	FIFO_USER_RESP,
	FIFO_USER_DATA,
	FIFO_USER_DATA_ACK,
	FIFO_USER_DATA_REJ,
	FIFO_CLIENT_REJ,
	FIFO_SHIELD_REQ,
	FIFO_BATCH_REQ,
	FIFO_USER_FILE,
	FIFO_FILE_REQ,
	FIFO_USER_FILE_RCV,
	FIFO_SIG_MSG,
}FIFO_MSG_TYPE;

typedef struct _fifomsgheader
{
	FIFO_MSG_TYPE type;
	size_t size; // demonstrate FIFO message content size
	int sockfd;
}FIFO_MSG_HEADER;

typedef struct _fifomsg
{
	FIFO_MSG_HEADER header;
	unsigned char msgbuf[1];
}FIFO_MSG;

typedef struct _userfile{
	uint32_t file_size;
	uint32_t data_id;
	uint8_t msgbuf[1];
	
	// uint32_t budget;
	// char filename[1];
}USER_FILE_HEADER;


typedef struct _session_close
{
	uint32_t session_id;
}SESSION_CLOSE_REQ;

typedef struct _session_msg1_response
{
	uint32_t sessionid;   // responder create a session ID and input here
	sgx_dh_dcap_msg1_t dh_msg1; // responder returns DCAP msg1
}SESSION_MSG1_RESP;

typedef struct _session_msg2
{
	uint32_t sessionid;
	sgx_dh_dcap_msg2_t dh_msg2;  // DCAP msg2
}SESSION_MSG2;

typedef struct _session_msg3
{
	uint32_t sessionid;
	sgx_dh_dcap_msg3_t dh_msg3;  // DCAP msg3
}SESSION_MSG3;

typedef struct _fifo_msg_req
{
	uint32_t session_id;
	size_t max_payload_size;
	size_t size;
	unsigned char buf[1];
}FIFO_MSGBODY_REQ;

typedef struct _fifo_user_req{
	uint32_t session_id; 
	size_t max_payload_size; // max payload size of resp message buf;
}FIFO_USER_REQ_MSG; // corresponding header type: FIFO_USER_REQ

typedef struct _fifo_user_data{
	uint32_t session_id;
	size_t size;
	uint32_t data_id;
	uint32_t budget;
	unsigned char buf[1]; // secure_msg_t;
}FIFO_USER_DATA_MSG;

typedef struct _fifo_client_req_msg{
	uint32_t session_id; // check:maybe no session id;
	uint32_t req_budget;
	uint32_t data_id;
}FIFO_CLIENT_REQ_MSG;




#ifdef __cplusplus
extern "C" {
#endif

int client_send_receive(FIFO_MSG *fiforequest, size_t fiforequest_size, FIFO_MSG **fiforesponse, size_t *fiforesponse_size);
int client_send_file(FIFO_MSG *file_header, size_t header_size, const char *filename, FIFO_MSG **fiforesponse, size_t *fiforesponse_size);
int user_send_ack();

#ifdef __cplusplus
}
#endif

#endif
