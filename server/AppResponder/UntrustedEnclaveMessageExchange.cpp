
#include "UntrustedEnclaveMessageExchange.h"
#include "EnclaveResponder_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include "fifo_def.h"
#include "config.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_quote_3.h"
#include "sgx_dcap_quoteverify.h"

#define BUFFER_SIZE 1024

uint32_t ecdsa_get_qe_target_info_ocall_edl(uint32_t* ret_status, sgx_target_info_t* qe_target_info){
    uint32_t ret = ecdsa_get_qe_target_info_ocall(qe_target_info);
    if (ret_status) *ret_status = ret;
    return ret;
}
uint32_t ecdsa_quote_generation_ocall_edl(uint32_t* ret_status, uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote_buffer){
    uint32_t ret = ecdsa_quote_generation_ocall(quote_size, app_report, quote_buffer);
    if (ret_status) *ret_status = ret;
    return ret;
}
uint32_t ecdsa_quote_verification_ocall_edl(uint32_t* ret_status, uint8_t* quote_buffer, uint32_t quote_size){
    uint32_t ret = ecdsa_quote_verification_ocall(quote_buffer, quote_size);
    if (ret_status) *ret_status = ret;
    return ret;
}

int client_send_receive(FIFO_MSG *fiforequest, size_t fiforequest_size, FIFO_MSG **fiforesponse, size_t *fiforesponse_size, sgx_enclave_id_t target_enclave_id);

uint32_t ecdsa_get_qe_target_info_ocall(sgx_target_info_t* qe_target_info){
#ifdef SGX_MODE_SIM
    return 0;
#else
    uint32_t ret = 0;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    sgx_target_info_t qe3_target_info;

    // Use out-of-proc mode (AESM daemon) instead of in-proc mode
    // This avoids issues with loading PCE enclave from OCALL context
    // Note: Do NOT call sgx_qe_set_enclave_load_policy or sgx_ql_set_path
    // The AESM daemon will handle PCE and QE3 loading
    
    qe3_ret = sgx_qe_get_target_info(&qe3_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    memcpy(qe_target_info, &qe3_target_info, sizeof(qe3_target_info));

CLEANUP:
    return ret;
#endif
}

uint32_t ecdsa_quote_generation_ocall(uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote_buffer){
#ifdef SGX_MODE_SIM
    if(quote_size) *quote_size = 0;
    return 0;
#else
    uint32_t ret = 0;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint8_t *p_quote_buffer = NULL;

    sgx_quote3_t *p_quote;
    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;
    qe3_ret = sgx_qe_get_quote_size(quote_size);
    if (SGX_QL_SUCCESS != qe3_ret)
    {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        goto CLEANUP;
    }
    p_quote_buffer = (uint8_t *)malloc(*quote_size);
    if (NULL == p_quote_buffer)
    {
        printf("Couldn't allocate quote_buffer\n");
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, *quote_size);

    // Get the Quote
    qe3_ret = sgx_qe_get_quote(app_report,
                               *quote_size,
                               p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret)
    {
        printf("Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        goto CLEANUP;
    }

    memcpy(quote_buffer, p_quote_buffer, *quote_size);
    p_quote = (sgx_quote3_t *)p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t *)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    return ret;
#endif
}

uint32_t ecdsa_quote_verification_ocall(uint8_t* quote_buffer, uint32_t quote_size)
{
#ifdef SGX_MODE_SIM
    return 0;
#else
    uint32_t ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t collateral_expiration_status = 1;

    // Untrusted quote verification
    // call DCAP quote verify library to get supplemental data size
    //
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t))
    {
        p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
    }
    else
    {
        if (dcap_ret != SGX_QL_SUCCESS)
            printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);

        if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t))
            printf("\tWarning: sgx_qv_get_quote_supplemental_data_size returned size is not same with header definition in SGX SDK, please make sure you are using same version of SGX SDK and DCAP QVL.\n");

        supplemental_data_size = 0;
    }

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    current_time = time(NULL);

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    dcap_ret = sgx_qv_verify_quote(
        (uint8_t*)quote_buffer, quote_size,
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,
        supplemental_data_size,
        p_supplemental_data);
    if (dcap_ret != SGX_QL_SUCCESS)
    {
        printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
    }

    // check verification result
    //
    switch (quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
        // check verification collateral expiration status
        // this value should be considered in your own attestation/verification policy
        //
        if (collateral_expiration_status == 0)
        {
            ret = 0;
        }
        else
        {
            printf("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.\n");
            ret = 1;
        }
        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
        ret = 1;
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        printf("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
        ret = -1;
        break;
    }

    return ret;
#endif
}

uint32_t session_request_ocall(sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id, sgx_enclave_id_t target_enclave_id) {
    FIFO_MSG msg1_request;
    FIFO_MSG *msg1_response = NULL;
    SESSION_MSG1_RESP *msg1_respbody = NULL;
    size_t msg1_resp_size;

    memset(&msg1_request, 0, sizeof(FIFO_MSG));
    msg1_request.header.type = FIFO_DH_REQ_MSG1;
    msg1_request.header.size = 0;

    if (client_send_receive(&msg1_request, sizeof(FIFO_MSG), &msg1_response, &msg1_resp_size, target_enclave_id) != 0 || msg1_response == NULL) {
        printf("fail to send and receive message.\n");
        return 1;
    }
    msg1_respbody = (SESSION_MSG1_RESP *)msg1_response->msgbuf;
    memcpy(dh_msg1, &msg1_respbody->dh_msg1, sizeof(sgx_dh_dcap_msg1_t));
    *session_id = msg1_respbody->sessionid;
    free(msg1_response);
    return 0;
}

uint32_t exchange_report_ocall(sgx_dh_dcap_msg2_t* dh_msg2, sgx_dh_dcap_msg3_t* dh_msg3, uint32_t session_id, sgx_enclave_id_t target_enclave_id) {
    FIFO_MSG *msg2 = NULL, *msg3 = NULL;
    FIFO_MSG_HEADER *msg2_header = NULL;
    SESSION_MSG2 *msg2_body = NULL;
    SESSION_MSG3 *msg3_body = NULL;
    size_t msg2size, msg3size;

    msg2size = sizeof(FIFO_MSG_HEADER) + sizeof(SESSION_MSG2);
    msg2 = (FIFO_MSG *)malloc(msg2size);
    if (!msg2) return 1;
    memset(msg2, 0, msg2size);

    msg2_header = (FIFO_MSG_HEADER *)msg2;
    msg2_header->type = FIFO_DH_MSG2;
    msg2_header->size = sizeof(SESSION_MSG2);

    msg2_body = (SESSION_MSG2 *)msg2->msgbuf;
    memcpy(&msg2_body->dh_msg2, dh_msg2, sizeof(sgx_dh_dcap_msg2_t));
    msg2_body->sessionid = session_id;

    if (client_send_receive(msg2, msg2size, &msg3, &msg3size, target_enclave_id) != 0) {
        free(msg2);
        printf("failed to send and receive message.\n");
        return 1;
    }
    msg3_body = (SESSION_MSG3 *)msg3->msgbuf;
    memcpy(dh_msg3, &msg3_body->dh_msg3, sizeof(sgx_dh_dcap_msg3_t));
    free(msg3);
    free(msg2);
    return 0;
}

uint32_t send_request_ocall(uint32_t session_id, void* req_message, size_t req_message_size, size_t max_payload_size, void* resp_message, size_t resp_message_size, sgx_enclave_id_t target_enclave_id) {
    FIFO_MSG *msgreq = NULL, *msgresp = NULL;
    FIFO_MSGBODY_REQ *msgbody;
    size_t reqsize, respsize;

    reqsize = sizeof(FIFO_MSG_HEADER) + sizeof(FIFO_MSGBODY_REQ) + req_message_size;
    msgreq = (FIFO_MSG *)malloc(reqsize);
    if (!msgreq) return 1;
    memset(msgreq, 0, reqsize);

    msgreq->header.type = FIFO_DH_MSG_REQ;
    msgreq->header.size = sizeof(FIFO_MSGBODY_REQ) + req_message_size;

    msgbody = (FIFO_MSGBODY_REQ *)msgreq->msgbuf;
    msgbody->max_payload_size = max_payload_size;
    msgbody->size = req_message_size;
    msgbody->session_id = session_id;
    memcpy(msgbody->buf, req_message, req_message_size);

    if (client_send_receive(msgreq, reqsize, &msgresp, &respsize, target_enclave_id) != 0) {
        free(msgreq);
        printf("fail to send and receive message.\n");
        return 1;
    }
    memcpy(resp_message, msgresp->msgbuf, msgresp->header.size < resp_message_size ? msgresp->header.size : resp_message_size);
    free(msgresp);
    free(msgreq);
    return 0;
}

uint32_t end_session_ocall(uint32_t session_id, sgx_enclave_id_t target_enclave_id) {
    FIFO_MSG *msgresp = NULL;
    FIFO_MSG *closemsg;
    SESSION_CLOSE_REQ *body;
    size_t reqsize, respsize;

    reqsize = sizeof(FIFO_MSG) + sizeof(SESSION_CLOSE_REQ);
    closemsg = (FIFO_MSG *)malloc(reqsize);
    if (!closemsg) return 1;
    memset(closemsg, 0, reqsize);

    closemsg->header.type = FIFO_DH_CLOSE_REQ;
    closemsg->header.size = sizeof(SESSION_CLOSE_REQ);

    body = (SESSION_CLOSE_REQ *)closemsg->msgbuf;
    body->session_id = session_id;

    if (client_send_receive(closemsg, reqsize, &msgresp, &respsize, target_enclave_id) != 0) {
        free(closemsg);
        printf("fail to send and receive message.\n");
        return 1;
    }
    free(msgresp);
    free(closemsg);
    return 0;
}

int client_send_receive(FIFO_MSG *fiforequest, size_t fiforequest_size, FIFO_MSG **fiforesponse, size_t *fiforesponse_size, sgx_enclave_id_t target_enclave_id)
{
    int ret = 0;
    long byte_num;
    char recv_msg[BUFFER_SIZE + 1] = {0};
    FIFO_MSG *response = NULL;

    struct sockaddr_in server_addr;
    int server_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock_fd == -1)
    {
        printf("socket error\n");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_server_port());
    inet_pton(AF_INET, get_server_addr(), &server_addr.sin_addr);

    if (connect(server_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        printf("connection error, %s, line %d.\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    if ((byte_num = send(server_sock_fd, (char *)fiforequest, (int)fiforequest_size, 0)) == -1)
    {
        printf("connection error, %s, line %d..\n", strerror(errno), __LINE__);
        ret = -1;
        goto CLEAN;
    }

    byte_num = recv(server_sock_fd, recv_msg, BUFFER_SIZE, 0);
    if (byte_num > 0)
    {
        if (byte_num > BUFFER_SIZE)
        {
            byte_num = BUFFER_SIZE;
        }

        recv_msg[byte_num] = '\0';

        response = (FIFO_MSG *)malloc((size_t)byte_num);
        if (!response)
        {
            printf("memory allocation failure.\n");
            ret = -1;
            goto CLEAN;
        }
        memset(response, 0, (size_t)byte_num);

        memcpy(response, recv_msg, (size_t)byte_num);

        *fiforesponse = response;
        *fiforesponse_size = (size_t)byte_num;

        ret = 0;
    }
    else if(byte_num < 0)
    {
        printf("server error, error message is %s!\n", strerror(errno));
        ret = -1;
    }
    else
    {
        printf("server exit!\n");
        ret = -1;
    }

CLEAN:
    close(server_sock_fd);
    return ret;
}
