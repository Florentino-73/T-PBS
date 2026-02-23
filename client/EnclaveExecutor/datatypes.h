#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"

#ifndef DATATYPES_H_
#define DATATYPES_H_

#define DH_KEY_SIZE        20
#define NONCE_SIZE         16
#define MAC_SIZE           16
#define HMAC_SIZE          32
#define MAC_KEY_SIZE       16
#define PADDING_SIZE       16

#define TAG_SIZE           16
#define IV_SIZE            12

#define DERIVE_MAC_KEY      0x0
#define DERIVE_SESSION_KEY  0x1
#define DERIVE_VK1_KEY      0x3
#define DERIVE_VK2_KEY      0x4

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

// uint32_t: can define multiple msg type;
// MSG TYPE: USER: CREATE DATA; RESTORE DATA;
//           CLIENT: REQUEST DATA; 
#define MESSAGE_EXCHANGE 0x0
#define ENCLAVE_TO_ENCLAVE_CALL 0x1


#define INVALID_ARGUMENT                   -2   ///< Invalid function argument
#define LOGIC_ERROR                        -3   ///< Functional logic error
#define FILE_NOT_FOUND                     -4   ///< File not found

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}

#define VMC_ATTRIBUTE_MASK  0xFFFFFFFFFFFFFFCB

typedef uint8_t dh_nonce[NONCE_SIZE];
typedef uint8_t cmac_128[MAC_SIZE];

#pragma pack(push, 1)

//Format of the AES-GCM message being exchanged between the source and the destination enclaves
typedef struct _secure_message_t
{
    uint32_t session_id; //Session ID identifying the session to which the message belongs
    sgx_aes_gcm_data_t message_aes_gcm_data;
}secure_message_t;

//Format of the input function parameter structure
typedef struct _ms_in_msg_exchange_t {
    uint32_t msg_type; //Type of Call E2E or general message exchange
    uint32_t target_fn_id; //Function Id to be called in Destination. Is valid only when msg_type=ENCLAVE_TO_ENCLAVE_CALL
    uint32_t inparam_buff_len; //Length of the serialized input parameters
    char inparam_buff[1]; //Serialized input parameters
} ms_in_msg_exchange_t;

//Format of the return value and output function parameter structure
typedef struct _ms_out_msg_exchange_t {
    uint32_t retval_len; //Length of the return value
    uint32_t ret_outparam_buff_len; //Length of the serialized return value and output parameters
    char ret_outparam_buff[1]; //Serialized return value and output parameters
} ms_out_msg_exchange_t;

//Session Tracker to generate session ids
typedef struct _session_id_tracker_t
{
    uint32_t          session_id;
}session_id_tracker_t;

#define PRIVACY_TYPE_DAYS 0X1
#define PRIVACY_TYPE_NUMS 0X2
#define PRIVACY_TYPE_EPSILON 0X3

typedef struct _stored_private_data{
    uint8_t privacy_type;
    uint32_t data_id;
    uint32_t remains_budget; // quantized float for epsilon;
    uint32_t data_size; // size of data(path);
    unsigned char path[10]; // path to store encrypted data
    unsigned char dscp[10]; // description of encrypted data
}stored_private_data;

typedef struct _resp_user_data{
    uint32_t data_id; // there is no need to resp user data;
    // sgx_ec256_dh_shared_t shared_key;
    // sgx_ec256_private_t prv_key;
}resp_user_data;

typedef struct _enc_user_data{
    uint32_t data_id;
    uint32_t budget;
    uint32_t data_len;
    char enc_data[1]; // data + usage; not encrypted;
}enc_user_data;

typedef struct _proposal{
    uint32_t data_id;
    uint32_t request_budget;
    uint32_t session_id;
    // uint32_t remain_budget;
}proposal_data;

typedef struct _proposal_grant{
    sgx_ec_key_128bit_t aek;
    uint32_t random;
    uint32_t data_id;
}proposal_grant;

typedef struct _batch_proposal_grant{
    uint32_t data_num;
    unsigned char buf[1];
}batch_proposal_grant;

/* GWAS structure begin */
# define heterozygous 0x1
# define homozygous 0x2
# define FILENAME_SIZE 13
# define DATA_ID_LENGTH 8

typedef struct _snp_data{
    uint8_t user_type; // 0 for control && 1 for case;
    uint32_t homo_num; // #(Ids of homozygous) 
    uint32_t SNPs[1]; // array to store SNPs, first homo, then heter; each id is a 4-byte int;
}SNP_DATA;

/* GWAS structure end */
typedef struct SNP {
    uint32_t rs_id_int;
    uint32_t counters[4];
    uint8_t data[276];
}SNP;



/* FIFO TYPE BEGIN */
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
}FIFO_MSG_TYPE;

typedef struct _fifomsgheader
{
	FIFO_MSG_TYPE type; // define body msg type;
	size_t size; // demonstrate FIFO message content size
	int sockfd; // identify clientfd;
}FIFO_MSG_HEADER;

typedef struct _fifomsg
{
	FIFO_MSG_HEADER header;
	unsigned char msgbuf[1];
}FIFO_MSG;

typedef struct _shield_req_msg{
	uint32_t session_id;
	uint8_t type; // 0 for store && 1 for request;
	size_t size; 
	unsigned char buf[1]; // secure_message_t(enc_user_data) ||  proposal_data
}SHIELD_REQ_MSG;

#define ID_SIZE 4

/* FIFO TYPE END */


#pragma pack(pop)

#endif
