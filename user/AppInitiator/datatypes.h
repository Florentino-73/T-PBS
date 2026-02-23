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
#define MAC_KEY_SIZE       16
#define PADDING_SIZE       16

#define TAG_SIZE        16
#define IV_SIZE            12

#define DERIVE_MAC_KEY      0x0
#define DERIVE_SESSION_KEY  0x1
#define DERIVE_VK1_KEY      0x3
#define DERIVE_VK2_KEY      0x4

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

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

typedef struct _enc_user_data{
    uint32_t data_id;
    uint32_t budget;
    uint32_t data_len;
    char enc_data[1]; // data + usage; not encrypted;
}enc_user_data;
typedef struct _user_data_header{
    uint32_t data_id;
    uint32_t budget;
    uint32_t data_len; // snp_size ---> enc_data size;
}user_data_header;


/* GWAS structure begin */
# define heterozygous 0x1;
# define homozygous 0x2;

typedef struct _snp_data{
    uint8_t user_type; // 0 for control && 1 for case;
    uint32_t homo_num; // #(Ids of homozygous) 
    uint32_t SNPs[1]; // array to store SNPs, first homo, then heter; each id is a 4-byte int;
}SNP_DATA;


typedef struct SNP {
    uint32_t rs_id_int;
    uint32_t counters[4];
    uint8_t data[276];
}SNP;

typedef struct element {
    uint32_t counters[4];
    uint8_t data[276];
}element;




typedef struct _shield_req_msg{
	uint32_t session_id;
	uint8_t type; // 0 for store && 1 for request;
	size_t size; 
	unsigned char buf[1]; // secure_message_t(enc_user_data) ||  proposal_data
}SHIELD_REQ_MSG;

typedef struct _proposal{
    uint32_t data_id;
    uint32_t request_budget;
    // uint32_t remain_budget;
}proposal_data;

/* GWAS structure end */

# define SNP_FILENAME_SIZE 32
# define SNP_CONTROL_SIZE 35

#pragma pack(pop)

#endif
