#include "LRU_Buffer.h"


int LRU_Cache::get(uint32_t data_id, uint32_t *budget){
    int ret=0;

    if (data_id == 0 || data_id > get_data_counter())
    {
        uint32_t tmp = 0;
        memcpy(budget, &tmp, sizeof(uint32_t));
        return 0;
    }

    uint32_t pid = data_id / ENTRY_PAGE_SIZE;
    uint32_t idx = (data_id-1) % ENTRY_PAGE_SIZE;

    std::map<uint32_t, CacheNode *>::iterator it = mp.find(pid);

    if (it != mp.end())
    { // find page;  // note: 512 may be wrong
        CacheNode *node = it->second;
        memcpy(budget, node->budget_page+idx, sizeof(uint32_t)); // cpy budget--> budget;
        ret = removeNode(node); 
        ret = setHead(node); 
        return ret;
    }
    else
    { // not exist, get from shield store and create new node;
        uint32_t *budgets=NULL;
        uint32_t *budgets_inside = (uint32_t*)malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE);

        if (budgets_inside == NULL){
            return -1;
        }

#ifdef _SHIELD
        shield_page_get(&budgets, pid); 
#endif
        if (budgets != NULL)
        { // if pid not exist in shield, then new pid;
            memcpy(budgets_inside, budgets, sizeof(uint32_t)*ENTRY_PAGE_SIZE);
        }
        else
        {
#ifdef _SHIELD
            uint32_t *budgets_out;
            if ((budgets_out=(uint32_t*)ocall_tc_malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE))==NULL)
            {
                return -1;
            }
            memset(budgets_out, 0, sizeof(uint32_t)*ENTRY_PAGE_SIZE);
            shield_page_insert(budgets_out, pid);
#endif
            memset(budgets_inside, 0, sizeof(uint32_t)*ENTRY_PAGE_SIZE);
        }

        CacheNode *new_node = new CacheNode(pid, budgets_inside);
        memcpy(budget, new_node->budget_page+idx, sizeof(uint32_t));
        
        // mp.insert(std::pair<uint32_t, CacheNode*>(pid, new_node));


        addHead(new_node); 

        return 0;
    }
    return 0;
}

int LRU_Cache::set(uint32_t data_id, uint32_t budget){
    if (data_id == 0) return -1;
    uint32_t pid = data_id / ENTRY_PAGE_SIZE;
    uint32_t idx = (data_id -1) % ENTRY_PAGE_SIZE; 
    map<uint32_t, CacheNode *>::iterator it = mp.find(pid);

    if (it != mp.end())
    {
        CacheNode *node = it->second;

        memcpy( (node->budget_page)+idx, &budget, sizeof(uint32_t));   

        removeNode(node);
        setHead(node);

        return 0;        
    }
    else
    {

        uint32_t *budgets;
        uint32_t *budgets_inside = (uint32_t*)malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE);

        if (budgets_inside == NULL){
            return -1;
        }
        memset(budgets_inside, 0, sizeof(uint32_t)*ENTRY_PAGE_SIZE);

        shield_page_get(&budgets, pid);
        if (budgets == NULL)
        {
            return -1;
        }

        memcpy(budgets_inside, budgets, sizeof(uint32_t)*ENTRY_PAGE_SIZE);
        CacheNode *new_node = new CacheNode(pid, budgets_inside);
        memcpy(budgets_inside+idx, &budget, sizeof(uint32_t));

        // mp[pid] = new_node;
        addHead(new_node);
        return 0;
    }
    return 0;
}

int LRU_Cache::set_batch(uint32_t page_id, vector<uint32_t> ids, vector<uint32_t>update_budgets){
    uint32_t data_id, idx;
    map<uint32_t, CacheNode *>::iterator it = mp.find(page_id);

    if (it != mp.end())
    {
        CacheNode *node = it->second;
        
        for (int i=0; i<ids.size(); i++)
        {
            data_id = ids[i];
            idx = (data_id - 1) % ENTRY_PAGE_SIZE;
            memcpy( (node->budget_page)+idx, &(update_budgets[i]), sizeof(uint32_t) );
        }
        removeNode(node);
        setHead(node);
        return 0;
    }else
    {
        uint32_t *budgets;
        uint32_t *budgets_inside = (uint32_t*)malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE);

        if (budgets_inside == NULL)
        {
            return -1;
        }
        memset(budgets_inside, 0, sizeof(uint32_t)*ENTRY_PAGE_SIZE);

        shield_page_get(&budgets, page_id);
        if (budgets == NULL)
        {
            return -1;
        }

        memcpy(budgets_inside, budgets, sizeof(uint32_t)*ENTRY_PAGE_SIZE);
        CacheNode *new_node = new CacheNode(page_id, budgets_inside);
        
        for (int i=0; i<ids.size(); i++){
            data_id = ids[i];
            idx = (data_id - 1) % ENTRY_PAGE_SIZE;
            memcpy( (new_node->budget_page)+idx, &(update_budgets[i]), sizeof(uint32_t) );
        }

        addHead(new_node);
        return 0;
    }

}

int LRU_Cache::removeNode(CacheNode *node)
{
    if (node == NULL)
    {
        return -1;
    }

    if (node->prev == NULL && node->next == NULL)
    {
        head = NULL;
        tail = NULL;
    }
    else if (node-> prev == NULL)
    {
        head = node->next;
        head->prev = NULL;
    }
    else if (node->next == NULL)
    {
        tail = node->prev;
        tail->next = NULL;
    }
    else
    {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }

    // SAFE_FREE(node->budget_page);
    // SAFE_FREE(node);
    return 0;    
}

int LRU_Cache::setHead(CacheNode *node){
    node->prev = NULL;
    node->next = head;

    if (head != NULL && tail == NULL)
    {
        return -1;
    }

    if (head == NULL && tail == NULL)
    {
        // if empty:
        head = node;
        tail = node;
    }
    else
    {
        node->next = head;
        head->prev = node;
        head = node;
    }

    return 0;
}

int LRU_Cache::addHead(CacheNode *node)
{
    int ret = 0;
    if (mp.size() > size)
    { // is_full
        CacheNode *tmp = tail;
        std::map<uint32_t, CacheNode*>::iterator it = mp.find(tmp->page_id);

        uint32_t *budgets_out;
        if ((budgets_out=(uint32_t*)ocall_tc_malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE))==NULL) return -1;

        memcpy(budgets_out, tmp->budget_page, sizeof(uint32_t)*ENTRY_PAGE_SIZE);

        shield_page_update(budgets_out, tmp->page_id); 


        ret = removeNode(tmp);
        if (tmp != NULL)
        {
            SAFE_FREE(tmp->budget_page);
            delete tmp;
        }
        mp.erase(it);
    }

    mp[node->page_id] = node;
    if (head == NULL && tail == NULL)
    {
        node->prev = NULL; 
        node->next = NULL;
        head = node;
        tail = node;
    }
    else
    {
        node->next = head;
        node->prev = NULL;
        head->prev = node;
        head = node;
    }

    return ret;
}

int LRU_Cache::user_insert_data(enc_user_data *user_data, uint8_t check_mode)
{ 
    uint32_t data_id = user_data->data_id;
    uint32_t budget = user_data->budget;
    uint32_t prev_budget;
    int ret;

    /* Set LRU data. */
    ret = get(data_id, &prev_budget);
    
    if (ret != 0 || (check_mode==1 && prev_budget!=0) ){ // MUST CHECK BUDGET 0
        return -1;
    }

    ret = set(data_id, budget); 
    return ret;
}

int LRU_Cache::get_batch(uint32_t data_num, uint32_t page_id, uint32_t *data_ids, uint32_t *prev_budgets)
{
    uint32_t cur_max_id = get_data_counter();
    uint32_t idx, data_id;
    bool zero_flags=true;

    if (prev_budgets == NULL)
    {
        return -1;
    }


    std::map<uint32_t, CacheNode *>::iterator it = mp.find(page_id);
    if (it != mp.end())
    {
        CacheNode *node = it->second;

        if (node == NULL)
        {
            return -1;
        }
        
        for (int i=0; i<data_num; i++)
        {
            data_id = data_ids[i];
            idx = (data_id-1) % ENTRY_PAGE_SIZE;

            memcpy(prev_budgets+i, node->budget_page+idx, sizeof(uint32_t));
        }


        removeNode(node);
        setHead(node);
        return 0;
    }
    else
    {
        uint32_t *budgets;
        uint32_t *budgets_inside = (uint32_t*)malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE);

        if (budgets_inside == NULL){
            return -1;
        }

        shield_page_get(&budgets, page_id); 
        if (budgets != NULL)
        { // if pid not exist in shield, then new pid;
            memcpy(budgets_inside, budgets, sizeof(uint32_t)*ENTRY_PAGE_SIZE);
        }
        else
        {
            uint32_t *budgets_out;
            if ((budgets_out=(uint32_t*)ocall_tc_malloc(sizeof(uint32_t)*ENTRY_PAGE_SIZE))==NULL) 
            {
                return -1;
            }

            memset(budgets_out, 0, sizeof(uint32_t)*ENTRY_PAGE_SIZE);
            memset(budgets_inside, 0, sizeof(uint32_t)*ENTRY_PAGE_SIZE);

            shield_page_insert(budgets_out, page_id);
        }

        CacheNode *new_node = new CacheNode(page_id, budgets_inside);

        for (int i=0; i<data_num; i++)
        {
            data_id = data_ids[i];
            idx = (data_id-1)%ENTRY_PAGE_SIZE;
            memcpy(prev_budgets+i, new_node->budget_page+idx, sizeof(uint32_t));
        }

        // mp.insert(std::pair<uint32_t, CacheNode*>(page_id, new_node));
        addHead(new_node); 

        return 0;
    }

}

int LRU_Cache::client_request_data(proposal_data *proposal){
    uint32_t prev_budget, remain_budget;
    uint32_t data_id = proposal->data_id;
    int ret; 

    ret = get(data_id, &prev_budget);
    remain_budget = prev_budget - proposal->request_budget;
    if (prev_budget < proposal->request_budget){
        return -1;
    }

    ret = set(data_id, remain_budget);
    return ret;
}

int LRU_Cache::client_request_data_batch(proposal_data_batch *proposal, vector<uint32_t> &update_ids){
    uint32_t remain_budget, prev_budget, request_budget;
    uint32_t data_num = proposal->data_num;
    uint32_t page_id = proposal->page_id;
    uint32_t *data_ids = (uint32_t *)proposal->buf;
    request_budget = proposal->request_budget;

    for (int i=0; i<data_num; i++)
    {
    }

    uint32_t *prev_budgets = (uint32_t *)malloc(sizeof(uint32_t)*data_num);
    if (!prev_budgets)
    {
        return -1;
    }

    int ret = get_batch(data_num, page_id, data_ids, prev_budgets);
    if (ret == -1)
    {
        return -1;
    }
    vector<uint32_t> update_budgets;

    for (int i=0; i<data_num; i++)
    {
        prev_budget = prev_budgets[i];
        if (prev_budget<request_budget)
        {
        }
        else
        {
            update_ids.push_back(data_ids[i]);
            update_budgets.push_back(prev_budget-request_budget);
        }
    }

    if (update_budgets.size() != 0)
    {
        ret = set_batch(page_id, update_ids, update_budgets);
    }

    SAFE_FREE(prev_budgets);
    return ret;   
}


uint32_t Executor_Manager::init_storage(uint32_t batch_id, uint32_t data_num, uint32_t *data_ids){
    vector<uint8_t *> *data_hash = new vector<uint8_t*>();
    batch_storage *batch_info = (batch_storage*)malloc(sizeof(batch_storage) + ID_SIZE*data_num);
    if (!batch_info)
    {
        return MALLOC_ERROR;
    }
     
    memcpy(batch_info->data_ids, data_ids, ID_SIZE*data_num);

    batch_info->batch_id = batch_id;
    batch_info->data_num = data_num;
    batch_info->fixed_flag = 0; // flag 0: not fixed;
    batch_info->data_hash = data_hash;

    batch_storage_map[batch_id] = batch_info;
    return SUCCESS;
}


uint32_t Executor_Manager::client_insert_req(add_hash_req *hash_req){
    // get batch_info

    map<uint32_t, batch_storage*>::iterator it = batch_storage_map.find(hash_req->batch_id);

    if (it != batch_storage_map.end()){
        batch_storage *batch_info = it->second;

        if(batch_info->fixed_flag == 1) return SERVER_REJ;

        vector<uint8_t *> *data_hash = batch_info->data_hash;
        for (int i=0; i<hash_req->data_num; i++){
            uint8_t *hash_val = (uint8_t *)malloc(SGX_HASH_SIZE); // hash: calculated through sgx_sha256_msg;
            if (!hash_val) return MALLOC_ERROR;
            memcpy(hash_val, hash_req->buf+i*SGX_HASH_SIZE, SGX_HASH_SIZE);
            data_hash->push_back(hash_val);
        }

    }else{
        return NULL_ERROR;
    }  

    return SUCCESS;
}


uint32_t Executor_Manager::compare_hash(vector<uint8_t *> *data_hash, uint8_t *compare_hash){
    uint32_t data_num = data_hash->size();

    for (int i=0; i<data_num; i++){
        uint8_t *stored_hash = data_hash->at(i);
        // show_ut(stored_hash, SGX_HASH_SIZE, "stored hash: ");
        // show_ut(compare_hash+i*SGX_HASH_SIZE, SGX_HASH_SIZE, "compare hash: ");
        if (strncmp((char *)stored_hash, (char *)compare_hash+i*SGX_HASH_SIZE, SGX_HASH_SIZE) != 0 ) return ERROR_HASH_MISMATCH;
    }
    
    return SUCCESS;
}


uint32_t Executor_Manager::executor_valid_req(get_key_req *key_req, vector<uint32_t> &data_ids){
    uint32_t batch_id = key_req->batch_id;

    map<uint32_t, batch_storage*>::iterator it = batch_storage_map.find(batch_id);

    if (it != batch_storage_map.end())
    {
        batch_storage *batch_info = it->second;
        if (batch_info == NULL)
        {
            return ERROR_TAG_MISMATCH;
        }

        vector<uint8_t *> *data_hash = batch_info->data_hash;

        if (key_req->data_num != data_hash->size())
        {
            return ERROR_TAG_MISMATCH;
        }

        // compare hash;
        uint32_t ret = compare_hash(data_hash, key_req->buf);
        if (ret != SUCCESS)
        {
            return ret;
        } 


        batch_info->fixed_flag = 1; // remove more info?
        data_ids.insert(data_ids.begin(), batch_info->data_ids, batch_info->data_ids+batch_info->data_num);

        SAFE_FREE(batch_info);
        batch_storage_map[batch_id] = NULL;
        return SUCCESS;
    }else
    {
        return NULL_ERROR;
    }
}


// uint32_t Executor_Manager::executor_get_key(get_key_req *key_req, char* msg_return, HDKeychain &seed){

//     uint32_t ret = executor_valid_req(key_req);

//     if (ret != SUCCESS){ return ret;
//     }else{
//         // return data_Ids
//         // generate keys;


//         // CLIENT_MSG_RETURN;
//         // generate msg_suc_resp�?//     }
    
// }
