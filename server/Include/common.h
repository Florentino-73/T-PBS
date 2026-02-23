#ifndef __COMMON_H
#define __COMMON_H

#include <stdbool.h>
#include <stdint.h>

/* PREDEFINED DATA */
#define MAC_SIZE 16
#define HMAC_SIZE 32
#define NAC_SIZE 16
// #define MANAGER_CAPACITY 10

extern uint32_t ENTRY_PAGE_SIZE;
extern uint32_t MANAGER_CAPACITY;

/* MAC BUffer */
struct mac_entry{
	int size;
	// uint8_t mac[MAC_SIZE*30];
	uint8_t mac[HMAC_SIZE*30];
};
typedef struct mac_entry MACentry;

struct macbuffer{
	MACentry* entry;
};
typedef struct macbuffer MACbuffer;

struct hashtable{
	int size;
	// struct budget_entry **table;
	struct page_entry **table;
};
typedef struct hashtable hashtable;

struct page_entry{
	uint32_t pid; 
	uint32_t *budgets;
	uint8_t nac[NAC_SIZE];
	// uint8_t mac[MAC_SIZE];
	uint8_t mac[HMAC_SIZE];
	struct page_entry *next; 
}; 
typedef struct page_entry page_entry;


struct job{ // note: buf: has max buff size;
	int client_sock;
	int job_type; // 0: insert data; 1: request_data
	char* buf ; // enc_user_data || proposal_data
};
typedef struct job job;

typedef struct {
	int client_sock_;
	int num_clients_;
    char* buf;
}EcallParams;

struct argument {
	int port_num;
	int num_threads;
	int max_buf_size;
	int bucket_size;
	int tree_root_size;
	int page_size;
	int manager_cap;
	bool key_opt;
	bool mac_opt;
};
typedef struct argument Arg;


#endif
