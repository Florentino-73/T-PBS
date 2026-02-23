#ifndef UTILITY_E2_H__
#define UTILITY_E2_H__
#include "stdint.h"
#include "datatypes.h"
#include "EnclaveResponder_t.h"



typedef struct _param_struct_t
{
    uint32_t var1;
    uint32_t var2;
}param_struct_t;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t get_data_counter();
uint32_t update_data_counter();
uint32_t update_leaf_counter();
uint32_t update_previous_data_counter();
uint32_t update_and_get_batch_counter();

uint32_t valid_data_id(uint32_t data_id);
uint32_t app_derive_key(const sgx_ec256_dh_shared_t *shared_key, const char *label, uint32_t label_length, sgx_ec_key_128bit_t *derived_key);

#ifdef _LOG
    void printf(const char *fmt, ...);
#else
    #define printf(fmt, ...) 
#endif

void show_ut(const uint8_t *var, size_t length, const char *fmt);

#ifdef __cplusplus
 }
#endif
#endif

