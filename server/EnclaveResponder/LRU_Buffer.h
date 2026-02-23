#ifndef __LRU_BUFFER_H
#define __LRU_BUFFER_H

#include <stdio.h>
#include <map>
#include <vector>

#include "datatypes.h"
#include "error_codes.h"
#include "ShieldStore/ShieldStore.h"

using namespace std;

struct CacheNode{
    uint32_t page_id;
    uint32_t *budget_page; // 1024 budgets;
    CacheNode *prev, *next;
    CacheNode(uint32_t pid, uint32_t *budget_pg): page_id(pid), budget_page(budget_pg), prev(NULL), next(NULL) {}
};

class LRU_Cache{
private:
    uint32_t size; 
    CacheNode *head, *tail;
    map<uint32_t, CacheNode*> mp;

public:
    LRU_Cache(uint32_t capacity){
        size = capacity;
        head = NULL;
        tail = NULL;
    }

    ~LRU_Cache(){
        map<uint32_t, CacheNode*>::iterator it;
        for (it = mp.begin(); it!=mp.end(); ){
            CacheNode *node = it->second;
            SAFE_FREE(node->budget_page);
            delete node;
            mp.erase(it++);
        }
    }

    int user_insert_data(enc_user_data *user_data, uint8_t check_mode);
    int client_request_data(proposal_data *proposal);
    int client_request_data_batch(proposal_data_batch *proposal, vector<uint32_t> &update_ids);

    int get(uint32_t data_id, uint32_t *budget);
    int set(uint32_t data_id, uint32_t budget);
    int removeNode(CacheNode *node);

    int get_batch(uint32_t data_num, uint32_t page_id, uint32_t *data_ids, uint32_t *prev_budgets);
    int set_batch(uint32_t page_id, vector<uint32_t> ids, vector<uint32_t>update_budgets);


    int setHead(CacheNode *node);
    int addHead(CacheNode *node);

};

typedef struct _batch_storage
{
    uint32_t batch_id;
    uint32_t data_num;
    uint8_t fixed_flag;
    std::vector<uint8_t *> *data_hash;
    uint32_t data_ids[1];
}batch_storage;


class Executor_Manager{
private:
    map<uint32_t, batch_storage*> batch_storage_map;
    uint32_t compare_hash(vector<uint8_t *> *data_hash, uint8_t *compare_hash);

public:
    Executor_Manager(){}
    ~Executor_Manager(){
        map<uint32_t, batch_storage*>::iterator it;
        for (it=batch_storage_map.begin(); it!=batch_storage_map.end(); ){
            batch_storage *batch_info = it->second;
            if (batch_info) {
                delete batch_info->data_hash;
                SAFE_FREE(batch_info);
            }
            batch_storage_map.erase(it++);
        }
    }

    uint32_t init_storage(uint32_t batch_id, uint32_t data_num, uint32_t *data_ids);
    uint32_t client_insert_req(add_hash_req *hash_req);
    uint32_t executor_valid_req(get_key_req *key_req,  vector<uint32_t> &data_ids);

};

#endif