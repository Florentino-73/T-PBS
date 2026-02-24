#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "sgx_tcrypto.h"
#include "EnclaveResponder_t.h"
#include <stdio.h>
#include <string.h>
#include "ShieldStore/ShieldStore.h"
#include "LRU_Buffer.h"

// Use existing printf from Utility_E2.h

#include "dcap_dh_def.h"
#include "tdcap_dh.h"
#ifdef __cplusplus
extern "C"
{
#endif
    uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t *peer_enclave_identity, sgx_enclave_id_t wasm_vm_enclave_id);
    uint32_t message_exchange_response_generator(uint8_t *decrypted_data, uint64_t decrypted_data_size, uint64_t max_resp_length, uint8_t *resp_buffer, size_t *resp_length);

#ifdef __cplusplus
}
#endif

#include <queue>
#include <vector>

// Global variables for business logic
hashtable *ht_enclave = nullptr;
MACbuffer *MACbuf_enclave = nullptr; 
Arg arg_enclave;
BucketMAC *MACTable = nullptr;
int ratio_root_per_buckets = 0;  // Match ShieldStore.h type
sgx_thread_mutex_t global_mutex;
sgx_thread_mutex_t *queue_mutex = nullptr;
sgx_thread_cond_t *job_cond = nullptr;
std::vector<std::queue<job *>> queue_;
uint32_t num = 0;  // Global thread counter
uint32_t ENTRY_PAGE_SIZE = 0;
uint32_t MANAGER_CAPACITY = 0;

#define MAX_SESSION_COUNT 16

// number of open sessions
uint32_t g_session_count = 0;

ATTESTATION_STATUS generate_session_id(uint32_t *session_id);
extern "C" ATTESTATION_STATUS end_session(uint32_t session_id);

// Forward declarations for business logic functions
uint32_t proposal_grant_return(uint32_t session_id, uint32_t data_id, char *resp_message, sgx_key_128bit_t kdk, uint8_t update_counter);
int proposal_grant_batch_return(uint32_t session_id, std::vector<uint32_t> &update_ids, char *secure_resp, HDKeychain &seed);

// Array of open session ids
session_id_tracker_t *g_session_id_tracker[MAX_SESSION_COUNT];

// Map between the source isv session id and the session information associated with that particular session
std::map<uint32_t, dh_session_t> g_dest_session_info_map;

// Create a session with the destination enclave (Gateway-style implementation)
ATTESTATION_STATUS create_session(dh_session_t *session_info, sgx_enclave_id_t wasm_vm_enclave_id)
{
    sgx_dh_dcap_msg1_t dh_msg1; // Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;    // Session Key
    sgx_dh_dcap_msg2_t dh_msg2; // Diffie-Hellman Message 2
    sgx_dh_dcap_msg3_t dh_msg3; // Diffie-Hellman Message 3
    uint32_t session_id;
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    if (!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_dcap_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_dcap_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_dcap_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

    // Intialize the session as a session initiator
    status = sgx_dh_dcap_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

    // Ocall to request for a session with the destination enclave and obtain session id and Message 1 if successful
    status = session_request_ocall(&retstatus, &dh_msg1, &session_id, wasm_vm_enclave_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS) {
            return ((ATTESTATION_STATUS)retstatus);
        }
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    // Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_dcap_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

    // Send Message 2 to Destination Enclave and get Message 3 in return
    status = exchange_report_ocall(&retstatus, &dh_msg2, &dh_msg3, session_id, wasm_vm_enclave_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS) {
            return ((ATTESTATION_STATUS)retstatus);
        }
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }

    // Process Message 3 obtained from the destination enclave
    status = sgx_dh_dcap_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

    // Verify the identity of the destination enclave
    if (verify_peer_enclave_trust(&responder_identity, wasm_vm_enclave_id) != SUCCESS)
    {
        return INVALID_SESSION;
    }

    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    session_info->session_id = session_id;
    session_info->active.counter = 0;
    session_info->status = ACTIVE;
    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
    return status;
}

// Request for the response size, send the request message to the destination enclave and receive the response message back
ATTESTATION_STATUS encrypt_to_enclave(dh_session_t *session_info,
                                                 uint8_t *inp_buff,
                                                 size_t inp_buff_len,
                                                 size_t max_out_buff_size,
                                                 uint8_t *out_buff,
                                                 size_t *out_buff_len,
                                                 sgx_enclave_id_t wasm_vm_enclave_id)
{
    const uint8_t *plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    secure_message_t *resp_message;
    plaintext = (const uint8_t *)(" ");
    plaintext_length = 0;

    resp_message = (secure_message_t *)out_buff;

    if (!session_info || !inp_buff)
    {
        return INVALID_PARAMETER_ERROR;
    }

    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;

    // Set the payload size to data to encrypt length
    resp_message->message_aes_gcm_data.payload_size = data2encrypt_length;
    if (data2encrypt_length + sizeof(secure_message_t) > max_out_buff_size) {
        return OUT_BUFFER_LENGTH_ERROR;
    }

    // Use the session nonce as the payload IV
    memcpy(resp_message->message_aes_gcm_data.reserved, &session_info->active.counter, sizeof(session_info->active.counter));

    // Set the session ID of the message to the current session id
    resp_message->session_id = session_info->session_id;

    // Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t *)inp_buff, data2encrypt_length,
                                        reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.payload)),
                                        reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                                        sizeof(resp_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                                        &(resp_message->message_aes_gcm_data.payload_tag));

    if (SGX_SUCCESS != status)
    {
        return status;
    }

    *out_buff_len = data2encrypt_length;
    return SUCCESS;
}

// Close a current session
ATTESTATION_STATUS close_session(dh_session_t *session_info, sgx_enclave_id_t wasm_vm_enclave_id)
{
    sgx_status_t status;
    uint32_t retstatus;

    if (!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    // Ocall to ask the destination enclave to end the session
    status = end_session_ocall(&retstatus, session_info->session_id, wasm_vm_enclave_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    return SUCCESS;
}

// Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if (!session_id)
    {
        return INVALID_PARAMETER_ERROR;
    }
    // if the session structure is uninitialized, set that as the next session ID
    for (int i = 0; i < MAX_SESSION_COUNT; i++)
    {
        if (g_session_id_tracker[i] == NULL)
        {
            *session_id = i;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;
}

/*---------------------------------------------------------------------------------------------*/

// Handle the request from ISV for a session
extern "C" ATTESTATION_STATUS session_request(sgx_dh_dcap_msg1_t *dh_msg1,
                                              uint32_t *session_id)
{
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    if (!session_id || !dh_msg1)
    {
        return INVALID_PARAMETER_ERROR;
    }
    // Intialize the session as a session responder
    status = sgx_dh_dcap_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

    // get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SUCCESS)
        return status; // no more sessions available

    // Allocate memory for the session id tracker
    g_session_id_tracker[*session_id] = (session_id_tracker_t *)malloc(sizeof(session_id_tracker_t));
    if (!g_session_id_tracker[*session_id])
    {
        return MALLOC_ERROR;
    }

    memset(g_session_id_tracker[*session_id], 0, sizeof(session_id_tracker_t));
    g_session_id_tracker[*session_id]->session_id = *session_id;
    session_info.status = IN_PROGRESS;

    // Generate Message1 that will be returned to ISV 
    status = sgx_dh_dcap_responder_gen_msg1((sgx_dh_dcap_msg1_t *)dh_msg1, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        SAFE_FREE(g_session_id_tracker[*session_id]);
        return status;
    }
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    // Store the session information under the corresponding ISV session id key
    g_dest_session_info_map.insert(std::pair<uint32_t, dh_session_t>(*session_id, session_info));

    return status;
}

// Verify Message 2, generate Message3 and exchange Message 3 with ISV
extern "C" ATTESTATION_STATUS exchange_report(sgx_dh_dcap_msg2_t *dh_msg2,
                                              sgx_dh_dcap_msg3_t *dh_msg3,
                                              uint32_t session_id)
{

    sgx_key_128bit_t dh_aek; // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;

    if (!dh_msg2 || !dh_msg3)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
    do
    {
        // Retrieve the session information for the corresponding ISV id
        std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
        if (it != g_dest_session_info_map.end())
        {
            session_info = &it->second;
        }
        else
        {
            status = INVALID_SESSION;
            break;
        }

        if (session_info->status != IN_PROGRESS)
        {
            status = INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        // Process message 2 from ISV and obtain message 3
        sgx_dh_session_enclave_identity_t initiator_identity;
        sgx_status_t se_ret = sgx_dh_dcap_responder_proc_msg2(dh_msg2,
                                                              dh_msg3,
                                                              &sgx_dh_session,
                                                              &dh_aek,
                                                              &initiator_identity);
        if (SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        // save the session ID, status and initialize the session nonce
        session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
        g_session_count++;
    } while (0);

    if (status != SUCCESS)
    {
        end_session(session_id);
    }

    return status;
}

// Process the request from the ISV and send the response message back to the ISV
extern "C" ATTESTATION_STATUS generate_response(secure_message_t *req_message,
                                                size_t req_message_size,
                                                size_t max_payload_size,
                                                secure_message_t *resp_message,
                                                size_t *resp_message_size,
                                                uint32_t session_id)
{
    const uint8_t *plaintext;
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    size_t resp_data_length;
    size_t resp_message_calc_size;
    uint8_t *resp_data;
    uint8_t l_tag[TAG_SIZE];
    size_t header_size, expected_payload_size;
    dh_session_t *session_info;
    uint32_t ret;
    sgx_status_t status;

    plaintext = (const uint8_t *)(" ");
    plaintext_length = 0;

    if (!req_message || !resp_message)
    {
        return INVALID_PARAMETER_ERROR;
    }

    // Get the session information from the map corresponding to the ISV id
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if (it != g_dest_session_info_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        return INVALID_SESSION;
    }

    if (session_info->status != ACTIVE)
    {
        return INVALID_SESSION;
    }

    // Set the decrypted data length to the payload size obtained from the message
    decrypted_data_length = req_message->message_aes_gcm_data.payload_size;
    
    header_size = sizeof(secure_message_t);
    expected_payload_size = req_message_size - header_size;

    // Verify the size of the payload
    if (expected_payload_size != decrypted_data_length) {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t *)malloc(decrypted_data_length);
    if (!decrypted_data)
    {
        return MALLOC_ERROR;
    }

    memset(decrypted_data, 0, decrypted_data_length);

    // Decrypt the request message payload from ISV
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, req_message->message_aes_gcm_data.payload,
                                        decrypted_data_length, decrypted_data,
                                        reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                                        sizeof(req_message->message_aes_gcm_data.reserved), &(req_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                                        &req_message->message_aes_gcm_data.payload_tag);

    if (SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        return status;
    }

    // Call the generic secret response generator for message exchange
    ret = message_exchange_response_generator(decrypted_data, decrypted_data_length, max_payload_size, (uint8_t *)resp_message, &resp_data_length);

    if (ret != 0)
    {
        SAFE_FREE(decrypted_data);
        return INVALID_SESSION;
    }

    if (resp_data_length > max_payload_size)
    {
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    resp_message_calc_size = sizeof(secure_message_t) + resp_data_length;

    if (resp_message_calc_size > *resp_message_size)
    {
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    *resp_message_size = resp_message_calc_size;

    SAFE_FREE(decrypted_data);

    return SUCCESS;
}

// Respond to the request from the ISV to close the session
extern "C" ATTESTATION_STATUS end_session(uint32_t session_id)
{
    ATTESTATION_STATUS status = SUCCESS;
    int i;
    dh_session_t session_info;
    // uint32_t session_id;

    // Get the session information from the map corresponding to the ISV id
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if (it != g_dest_session_info_map.end())
    {
        session_info = it->second;
    }
    else
    {
        return INVALID_SESSION;
    }

    // session_id = session_info.session_id;
    // Erase the session information for the current session
    g_dest_session_info_map.erase(session_id);

    // Update the session id tracker
    if (g_session_count > 0)
    {
        // check if session exists
        for (i = 1; i <= MAX_SESSION_COUNT; i++)
        {
            if (g_session_id_tracker[i - 1] != NULL && g_session_id_tracker[i - 1]->session_id == session_id)
            {
                memset(g_session_id_tracker[i - 1], 0, sizeof(session_id_tracker_t));
                SAFE_FREE(g_session_id_tracker[i - 1]);
                g_session_count--;
                break;
            }
        }
    }

    return status;
}

/**
 * init enclave values
 **/
void ecall_enclave_init_values(hashtable *ht_, MACbuffer *MACbuf_, Arg arg)
{
    ht_enclave = ht_;
    MACbuf_enclave = MACbuf_;
    arg_enclave = arg;
    ENTRY_PAGE_SIZE = arg.page_size;
    MANAGER_CAPACITY = arg.manager_cap;

    // set the ratio of subtree root node inside the enclave memory
    // over total hash value of buckets
    ratio_root_per_buckets = ht_enclave->size / arg_enclave.tree_root_size;

    MACTable = (BucketMAC *)malloc(sizeof(BucketMAC) * arg_enclave.tree_root_size);
    for (int i = 0; i < arg_enclave.tree_root_size; i++)
    {
        memset(MACTable[i].mac, 0, HMAC_SIZE);
    }

    // Initialize mutex variables
    sgx_thread_mutex_init(&global_mutex, NULL);

    queue_mutex = (sgx_thread_mutex_t *)malloc(sizeof(sgx_thread_mutex_t) * arg_enclave.num_threads);  // each mutext for a thread;
    job_cond =
        (sgx_thread_cond_t *)malloc(sizeof(sgx_thread_cond_t) * arg_enclave.num_threads);  // multiple sgx_thread_cond_t, each for a thread.
    // DH_Seeds = (HDKeychain *)malloc(sizeof(DHKeychain)*args.num_threads);

    for (int i = 0; i < arg_enclave.num_threads; i++)
    {
        std::queue<job *> tmp;  // a queue for each thread;
        queue_.push_back(tmp);
    }
}

uint32_t ecall_message_pass_switchless(uint32_t client_sock, uint8_t *msg, uint32_t data_length)
{
    dh_session_t *session_info;
    job *new_job = NULL;
    uint32_t thread_id = 0;

    SHIELD_REQ_MSG *shield_req = (SHIELD_REQ_MSG *)msg;
    uint32_t msg_size = shield_req->size;
    uint32_t session_id = shield_req->session_id;

    switch (shield_req->type)
    {
        case 0:
        {  // user insert;
            enc_user_data *user_data = (enc_user_data *)shield_req->buf;
            uint32_t page_id = user_data->data_id / ENTRY_PAGE_SIZE;
            thread_id = ht_hash(page_id, arg_enclave.num_threads);

            new_job = (job *)malloc(sizeof(job));
            new_job->job_type = 0;
            new_job->client_sock = client_sock;
            new_job->buf = (char *)malloc(msg_size);  // sizeof(enc_user_data)
            memcpy(new_job->buf, shield_req->buf, msg_size);

            sgx_thread_mutex_lock(&queue_mutex[thread_id]);
            queue_[thread_id].push(new_job);
            sgx_thread_cond_signal(&job_cond[thread_id]);
            sgx_thread_mutex_unlock(&queue_mutex[thread_id]);
        }
        break;
        case 1:
        {  // req single data
            proposal_data *proposal = (proposal_data *)shield_req->buf;

            uint32_t page_id = proposal->data_id / ENTRY_PAGE_SIZE;

            new_job = (job *)malloc(sizeof(job));
            new_job->job_type = 1;  // usage;
            new_job->client_sock = client_sock;

            new_job->buf = (char *)malloc(sizeof(proposal_data));
            if (new_job->buf == NULL) return MALLOC_ERROR;
            memcpy(new_job->buf, shield_req->buf, sizeof(proposal_data));

            thread_id = ht_hash(page_id, arg_enclave.num_threads);

            sgx_thread_mutex_lock(&queue_mutex[thread_id]);
            queue_[thread_id].push(new_job);
            sgx_thread_cond_signal(&job_cond[thread_id]);
            sgx_thread_mutex_unlock(&queue_mutex[thread_id]);
        }
        break;
        case 2:  // proposal_data_batch
        case 3:
        {
            proposal_data_batch *proposal = (proposal_data_batch *)shield_req->buf;

            new_job = (job *)malloc(sizeof(job));
            if (new_job == NULL) return MALLOC_ERROR;

            new_job->buf = (char *)malloc(msg_size);
            if (new_job->buf == NULL) return MALLOC_ERROR;

            memcpy(new_job->buf, shield_req->buf, msg_size);
            new_job->job_type = shield_req->type;  // proposal_data_batch;
            new_job->client_sock = client_sock;

            thread_id = ht_hash(proposal->page_id, arg_enclave.num_threads);
            sgx_thread_mutex_lock(&queue_mutex[thread_id]);
            queue_[thread_id].push(new_job);
            sgx_thread_cond_signal(&job_cond[thread_id]);
            sgx_thread_mutex_unlock(&queue_mutex[thread_id]);

            // later: optimize process;
        }
        break;
        case 4:
        case 5:
        {  // CLIENT INSERT HASH or executor get key
            uint32_t page_id;
            memcpy(&page_id, shield_req->buf, sizeof(uint32_t));

            new_job = (job *)malloc(sizeof(job));
            if (new_job == NULL) return MALLOC_ERROR;
            new_job->buf = (char *)malloc(msg_size - sizeof(uint32_t));
            if (!new_job->buf) return MALLOC_ERROR;

            memcpy(new_job->buf, shield_req->buf + sizeof(uint32_t), msg_size - sizeof(uint32_t));
            new_job->job_type = shield_req->type;
            new_job->client_sock = client_sock;

            get_key_req *key_req = (get_key_req *)(shield_req->buf + sizeof(uint32_t));
            // show_ut(key_req->buf, SGX_HASH_SIZE, "msg pass hash");

            thread_id = ht_hash(page_id, arg_enclave.num_threads);
            sgx_thread_mutex_lock(&queue_mutex[thread_id]);
            queue_[thread_id].push(new_job);
            sgx_thread_cond_signal(&job_cond[thread_id]);
            sgx_thread_mutex_unlock(&queue_mutex[thread_id]);

        }
        break;
        case 6:
        {  // USER REQUEST to get key & data_id;
            uint32_t data_id;
            update_data_counter();
            data_id = get_data_counter();
            job *new_job = (job *)malloc(sizeof(job));
            if (!new_job) return MALLOC_ERROR;
            new_job->buf = (char *)malloc(sizeof(user_req_key));
            if (!new_job->buf) return MALLOC_ERROR;

            new_job->job_type = 6;
            new_job->client_sock = client_sock;
            user_req_key *req = (user_req_key *)new_job->buf;
            req->data_id = data_id;
            req->session_id = session_id;

            uint32_t page_id = data_id / ENTRY_PAGE_SIZE;
            thread_id = ht_hash(page_id, arg_enclave.num_threads);
            sgx_thread_mutex_lock(&queue_mutex[thread_id]);
            queue_[thread_id].push(new_job);
            sgx_thread_cond_signal(&job_cond[thread_id]);
            sgx_thread_mutex_unlock(&queue_mutex[thread_id]);
        }
        break;
    }
    return SUCCESS;
}

/**
 * processing server working threads
 **/
void ecall_worker_thread(hashtable *ht_, MACbuffer *MACbuf_)
{
    uint32_t job0_cnt = 0, job6_cnt = 0;
    uint32_t job0_iter = 1, job6_iter = 1;

    int thread_id;
    job *cur_job = NULL;
    char *cipher = NULL;
    int job_type;

    ht_enclave = ht_;
    MACbuf_enclave = MACbuf_;
    HDKeychain DH_Seed;
    LRU_Cache budget_manager(MANAGER_CAPACITY);
    Executor_Manager executor_manager;

    sgx_thread_mutex_lock(&global_mutex);

    thread_id = num;
    num += 1;

    sgx_thread_mutex_init(&queue_mutex[thread_id], NULL);
    sgx_thread_cond_init(&job_cond[thread_id], NULL);
    sgx_thread_mutex_unlock(&global_mutex);
    sgx_thread_mutex_lock(&queue_mutex[thread_id]);

    while (1)
    {
        if (queue_[thread_id].size() == 0)
        {
            int tmp = sgx_thread_cond_wait(&job_cond[thread_id], &queue_mutex[thread_id]);
            continue;
        }
        cur_job = queue_[thread_id].front();
        sgx_thread_mutex_unlock(&queue_mutex[thread_id]);

        job_type = cur_job->job_type;
        cipher = cur_job->buf;

        switch (job_type)
        {
            case 0:
            { /* Job type 0: user send data; */
                do
                {
                    uint8_t mode = (job0_cnt % job0_iter == 0) ? 1 : 0;
                    job0_cnt += 1;

                    enc_user_data *user_data = (enc_user_data *)cipher;
                    int ret = budget_manager.user_insert_data(user_data,
                                                              mode);  // Note:ADD INSERT COUNTER TO PREVENT REPLY ATTACK;

                    if (job0_cnt % job0_iter == 0)
                    {
                        if (ret != 0)
                        {
                        }
                        else
                        {
                            user_msg_return(0, cur_job->client_sock);
                        }
                        break;
                    }
                } while (1);
            }
            break;
            case 1:
            {   // Job type 1: client request data
                proposal_data *proposal = (proposal_data *)cipher;
                uint32_t data_id = proposal->data_id;

                /* KeyGen  */
                sgx_key_128bit_t kdk;
                sgx_ec256_dh_shared_t enc_key;
                DH_Seed.get_dh_key(data_id, &enc_key);  // get enc_key;
                uint32_t status = app_derive_key(&enc_key, "AEK", (uint32_t)(sizeof("AEK") - 1),
                                             &kdk);  // get encrypt key;

                /* Update budget */
                int ret = budget_manager.client_request_data(proposal);
                if (ret != 0)
                {
                    client_msg_return(ret, cur_job->client_sock, 0, NULL, job_type);
                    break;
                }

                /* Return update msg | proposal grant */
                size_t secure_msg_size = sizeof(secure_message_t) + sizeof(proposal_grant);
                char *secure_msg = (char *)malloc(secure_msg_size);
                ret = proposal_grant_return(proposal->session_id, proposal->data_id, secure_msg, kdk, 1);
                if (ret != 0)
                {
                    client_msg_return(ret, cur_job->client_sock, 0, NULL, job_type);
                }
                else
                {
                    client_msg_return(0, cur_job->client_sock, secure_msg_size, secure_msg, job_type);
                }

                SAFE_FREE(secure_msg);
            }
            break;
            case 2:
            {
                proposal_data_batch *proposal = (proposal_data_batch *)cipher;
                uint32_t data_num = proposal->data_num;
                uint32_t *data_ids = (uint32_t *)proposal->buf;
                uint32_t data_id;

                for (int i = 0; i < data_num; i++)
                {
                }

                // update budget
                std::vector<uint32_t> update_ids;

                int ret;
                ret = budget_manager.client_request_data_batch(proposal, update_ids);

                if (ret != 0 or update_ids.size() == 0)
                {
                    client_msg_return(1, cur_job->client_sock, 0, NULL, job_type);
                }
                else
                {
                    // return 128bit_aek && ids && random ;
                    uint32_t update_num = update_ids.size();
                    for (int i = 0; i < update_num; i++)
                    {
                    }

                    size_t secure_msg_size =
                        sizeof(secure_message_t) + sizeof(batch_proposal_grant) + update_num * MAC_KEY_SIZE + update_num * ID_SIZE;
                    char *secure_msg = (char *)malloc(secure_msg_size);

                    ret = proposal_grant_batch_return(proposal->session_id, update_ids, secure_msg, DH_Seed);

                    if (ret != 0)
                    {
                        client_msg_return(ret, cur_job->client_sock, 0, NULL, job_type);
                    }
                    else
                    {
                        client_msg_return(0, cur_job->client_sock, secure_msg_size, secure_msg, job_type);
                    }
                    SAFE_FREE(secure_msg);
                }
            }
            break;
            case 3:
            {   // CLIENT REQUEST ASYN;
                proposal_data_batch *proposal = (proposal_data_batch *)cipher;
                uint32_t data_num = proposal->data_num;
                uint32_t *data_ids = (uint32_t *)proposal->buf;
                uint32_t data_id;

                std::vector<uint32_t> update_ids;
                int tmp_ret = budget_manager.client_request_data_batch(proposal, update_ids);

                if (tmp_ret != 0 || update_ids.size() == 0)
                {
                    client_msg_return(2, cur_job->client_sock, 0, NULL, job_type);
                }
                else
                {
                    uint32_t new_batch_id = update_and_get_batch_counter();
                    int ret = executor_manager.init_storage(new_batch_id, proposal->data_num, data_ids);
                    if (ret != 0)
                    {
                        client_msg_return(1, cur_job->client_sock, 0, NULL, job_type);
                    }
                    else
                    {

                        client_msg_return(0, cur_job->client_sock, sizeof(uint32_t), (char *)&new_batch_id, job_type);
                    }
                }
            }
            break;
            case 4:
            {   // CLIENT INSERT HASH
                add_hash_req *hash_req = (add_hash_req *)cipher;
                uint32_t ret = executor_manager.client_insert_req(hash_req);  // NOTE: add page_id in msg_pass thread;

                if (ret != 0)
                {
                    client_msg_return(1, cur_job->client_sock, 0, NULL, job_type);
                }
                else
                {
                    client_msg_return(0, cur_job->client_sock, 0, NULL, job_type);
                }
            }
            break;
            case 5:
            {   // CLIENT REQUEST KEY;
                get_key_req *key_req = (get_key_req *)cipher;
                vector<uint32_t> data_ids;

                uint32_t ret = executor_manager.executor_valid_req(key_req, data_ids);

                if (ret != 0)
                {
                    client_msg_return(1, cur_job->client_sock, 0, NULL, job_type);
                }
                else
                {
                    size_t secure_msg_size = sizeof(secure_message_t) + sizeof(batch_proposal_grant) + data_ids.size() * MAC_KEY_SIZE +
                                             data_ids.size() * ID_SIZE;
                    char *secure_msg = (char *)malloc(secure_msg_size);

                    ret = proposal_grant_batch_return(key_req->session_id, data_ids, secure_msg, DH_Seed);

                    if (ret != 0)
                    {
                        client_msg_return(ret, cur_job->client_sock, 0, NULL, job_type);
                    }
                    else
                    {
                        // printf("return secure msg size: %u\n", secure_msg_size);
                        client_msg_return(0, cur_job->client_sock, secure_msg_size, secure_msg, job_type);
                    }
                    SAFE_FREE(secure_msg);
                }
            }
            break;
            case 6:
            {   // user request key;
                do
                {
                    job6_cnt += 1;
                    uint8_t mode = (job6_cnt % job6_iter == 0) ? 1 : 0;

                    user_req_key *user_req = (user_req_key *)cipher;
                    sgx_ec256_dh_shared_t enc_key;
                    sgx_ec_key_128bit_t aek;
                    DH_Seed.get_dh_key(user_req->data_id, &enc_key);
                    uint32_t status = app_derive_key(&enc_key, "AEK", (uint32_t)(sizeof("AEK") - 1),
                                                 &aek);  // get encrypt key;

                    /* Return update msg | proposal grant */
                    size_t secure_msg_size = sizeof(secure_message_t) + sizeof(proposal_grant);
                    char *secure_msg = (char *)malloc(secure_msg_size);
                    uint32_t ret = proposal_grant_return(user_req->session_id, user_req->data_id, secure_msg, aek, mode);

                    // NOTE: IF BENCHMARK TEST, NO CLIENT_MSG_RETURN;
                    if (job6_cnt % job6_iter == 0)
                    {
                        if (ret != 0)
                        {
                            client_msg_return(ret, cur_job->client_sock, 0, NULL, job_type);
                        }
                        else 
                        {
                            // printf("proposal granted return..\n");
                            client_msg_return(0, cur_job->client_sock, secure_msg_size, secure_msg, job_type);
                        }
                        SAFE_FREE(secure_msg);
                        break;
                    }
                } while (1);
            }
            break;
        }

        sgx_thread_mutex_lock(&queue_mutex[thread_id]);
        queue_[thread_id].pop();
        free(cipher);
        free(cur_job);
    }

    return;
}

int proposal_grant_batch_return(uint32_t session_id, std::vector<uint32_t> &update_ids, char *secure_resp, HDKeychain &seed)
{
    dh_session_t *session_info;
    secure_message_t *tmp_secure_resp;

    sgx_key_128bit_t kdk;
    sgx_ec256_dh_shared_t enc_key;
    uint32_t data_id, data_num, resp_secure_length;
    batch_proposal_grant *key_resp;
    uint32_t random;
    sgx_read_rand((unsigned char *)&random, sizeof(random));

    if (!secure_resp)
    {
        return -1;
    }

    data_num = update_ids.size();
    resp_secure_length = sizeof(batch_proposal_grant) + data_num * MAC_KEY_SIZE + data_num * sizeof(uint32_t);

    key_resp = (batch_proposal_grant *)malloc(resp_secure_length);
    if (!key_resp) return MALLOC_ERROR;

    key_resp->data_num = data_num;
    for (int i = 0; i < data_num; i++)
    {
        data_id = update_ids[i];
        seed.get_dh_key(data_id, &enc_key);  // get enc_key;
        uint32_t status = app_derive_key(&enc_key, "AEK", (uint32_t)(sizeof("AEK") - 1),
                                     &kdk);  // get encrypt key;

        memcpy(key_resp->buf + i * sizeof(uint32_t), &data_id, sizeof(uint32_t));
        memcpy(key_resp->buf + data_num * sizeof(uint32_t) + i * MAC_KEY_SIZE, kdk, MAC_KEY_SIZE);
    }

    /* GET THE SEESION INFO */
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if (it != g_dest_session_info_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        SAFE_FREE(key_resp);
        return INVALID_SESSION;
    }

    if (session_info->status != ACTIVE) return INVALID_SESSION;
    memset(secure_resp, 0, sizeof(secure_message_t) + resp_secure_length);

    tmp_secure_resp = (secure_message_t *)secure_resp;
    tmp_secure_resp->session_id = session_info->session_id;
    tmp_secure_resp->message_aes_gcm_data.payload_size = (uint32_t)resp_secure_length;

    memcpy(&tmp_secure_resp->message_aes_gcm_data.reserved, &session_info->active.counter, sizeof(session_info->active.counter));

    sgx_status_t status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t *)key_resp, (uint32_t)resp_secure_length,
                                                     reinterpret_cast<uint8_t *>(&(tmp_secure_resp->message_aes_gcm_data.payload)),  // dest
                                                     reinterpret_cast<uint8_t *>(&(tmp_secure_resp->message_aes_gcm_data.reserved)),
                                                     sizeof(tmp_secure_resp->message_aes_gcm_data.reserved), NULL, 0,
                                                     &(tmp_secure_resp->message_aes_gcm_data.payload_tag));

    if (status != SGX_SUCCESS)
    {
        SAFE_FREE(key_resp);
        return -1;
    }

    SAFE_FREE(key_resp);
    return 0;
}

uint32_t proposal_grant_return(uint32_t session_id, uint32_t data_id, char *resp_message, sgx_key_128bit_t kdk, uint8_t update_counter)
{
    size_t resp_data_length;
    uint8_t l_tag[TAG_SIZE];
    dh_session_t *session_info;
    secure_message_t *temp_resp_message;
    uint32_t ret;
    uint32_t random;
    sgx_read_rand((unsigned char *)&random, sizeof(random));
    sgx_status_t status;
    proposal_grant *resp_data;

    if (!resp_message)
    {
        return NULL_ERROR;
    }

    /* set resp_data: proposal grant */
    resp_data_length = sizeof(proposal_grant);
    resp_data = (proposal_grant *)malloc(resp_data_length);
    if (!resp_data) return MALLOC_ERROR;

    memcpy(resp_data->aek, kdk, 16);

    resp_data->data_id = data_id;
    resp_data->random = random;

    /* Get the session information; */
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if (it != g_dest_session_info_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        return INVALID_SESSION;
    }
    if (session_info->status != ACTIVE)
    {
        return INVALID_SESSION;
    }

    temp_resp_message = (secure_message_t *)malloc(resp_data_length + sizeof(secure_message_t));

    if (!temp_resp_message) return MALLOC_ERROR;
    memset(temp_resp_message, 0, sizeof(secure_message_t) + resp_data_length);

    temp_resp_message->session_id = session_info->session_id;
    temp_resp_message->message_aes_gcm_data.payload_size = (uint32_t)resp_data_length;

    // // increment the session nonce;
    if (update_counter == 1)
    {
        session_info->active.counter = session_info->active.counter + 1;
    }

    memcpy(&temp_resp_message->message_aes_gcm_data.reserved, &session_info->active.counter, sizeof(session_info->active.counter));

    // printf("RETURNED KEY COUNTER IS: %u.\n", *((uint32_t *)temp_resp_message->message_aes_gcm_data.reserved));
    // show_ut(temp_resp_message->message_aes_gcm_data.reserved, 12, "reserved
    // bytes: ");
    
    // prepare the response message with entrypted payload;
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t *)resp_data, (uint32_t)resp_data_length,
                                        reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.payload)),  // dest
                                        reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.reserved)),
                                        sizeof(temp_resp_message->message_aes_gcm_data.reserved), NULL, 0,
                                        &(temp_resp_message->message_aes_gcm_data.payload_tag));

    if (status != SGX_SUCCESS)
    {
        SAFE_FREE(temp_resp_message);
        return status;
    }

    memcpy(resp_message, temp_resp_message, sizeof(secure_message_t) + resp_data_length);

    SAFE_FREE(temp_resp_message);
    SAFE_FREE(resp_data);
    return SUCCESS;
}

// Remove duplicate implementations - use existing ones from Utility_E2.h
