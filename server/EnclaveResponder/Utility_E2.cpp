#include "Utility_E2.h"

#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "sgx_eid.h"
#include "stdlib.h"
#include "string.h"
#include <atomic>

std::atomic<uint32_t> previous_data_counter(0), mono_data_counter(0), mono_leaf_counter(0), mono_batch_counter(0);
// uint32_t previous_data_counter = 0;  // note: this counter is the lower bound of current data id;
// uint32_t mono_data_counter = 0;      // note: monotonic counter to assign data id;
// uint32_t mono_leaf_counter = 0;      // note: monotonic counter to track the leaf data;
// uint32_t mono_batch_counter = 0;     // note: monotonic counter to track batch_id;

#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) + 4)

void PRINT_BYTE_ARRAY(void *mem, uint32_t len)
{
  (void)mem;
  (void)len;
  return;
}

uint32_t update_data_counter()
{
  mono_data_counter += 1;
  return 0;
}

uint32_t get_data_counter() 
{ 
  return mono_data_counter.load(); 
}

uint32_t update_leaf_counter()
{
  mono_leaf_counter += 1;
  return 0;
}

uint32_t update_and_get_batch_counter()
{
  mono_batch_counter += 1;
  return mono_batch_counter.load();
}

uint32_t update_previous_data_counter()
{
  previous_data_counter += 1;
  return 0;
}

uint32_t valid_data_id(uint32_t data_id)
{
  if (previous_data_counter >= data_id || data_id > mono_data_counter || data_id < 0)
    {
      return -1;
    }
  return 0;
}


uint32_t app_derive_key(const sgx_ec256_dh_shared_t *shared_key, const char *label, uint32_t label_length, sgx_ec_key_128bit_t *derived_key)
{
  sgx_status_t se_ret = SGX_SUCCESS;
  uint8_t cmac_key[MAC_KEY_SIZE];
  sgx_ec_key_128bit_t key_derive_key;
  if (!shared_key || !derived_key || !label)
    {
      return SGX_ERROR_INVALID_PARAMETER;
    }

  /*check integer overflow */
  if (label_length > EC_DERIVATION_BUFFER_SIZE(label_length))
    {
      return SGX_ERROR_INVALID_PARAMETER;
    }

  memset(cmac_key, 0, MAC_KEY_SIZE);
  se_ret = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *)cmac_key, (uint8_t *)shared_key, sizeof(sgx_ec256_dh_shared_t),
                                    (sgx_cmac_128bit_tag_t *)&key_derive_key);
  if (SGX_SUCCESS != se_ret)
    {
      memset_s(&key_derive_key, sizeof(key_derive_key), 0, sizeof(key_derive_key));
      // INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret);
      return se_ret;
    }
  /* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
  uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE(label_length);
  uint8_t *p_derivation_buffer = (uint8_t *)malloc(derivation_buffer_length);
  if (p_derivation_buffer == NULL)
    {
      return SGX_ERROR_OUT_OF_MEMORY;
    }
  memset(p_derivation_buffer, 0, derivation_buffer_length);

  /*counter = 0x01 */
  p_derivation_buffer[0] = 0x01;
  /*label*/
  memcpy(&p_derivation_buffer[1], label, label_length);
  /*output_key_len=0x0080*/
  uint16_t *key_len = (uint16_t *)&p_derivation_buffer[derivation_buffer_length - 2];
  *key_len = 0x0080;

  se_ret = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *)&key_derive_key, p_derivation_buffer, derivation_buffer_length,
                                    (sgx_cmac_128bit_tag_t *)derived_key);
  memset_s(&key_derive_key, sizeof(key_derive_key), 0, sizeof(key_derive_key));
  free(p_derivation_buffer);
  // if(SGX_SUCCESS != se_ret)
  // {
  //     // INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret);
  // }
  return se_ret;
}

void show_ut(const uint8_t *var, size_t length, const char *fmt)
{
  (void)var;
  (void)length;
  (void)fmt;
  return;
}

#include <stdio.h>  // vsnprintf
#ifdef _LOG
  void printf(const char *fmt, ...)
  {
      char buf[BUFSIZ] = {'\0'};
      va_list ap;
      va_start(ap, fmt);
      vsnprintf(buf, BUFSIZ, fmt, ap);
      va_end(ap);
      ocall_printf(buf);
  }
#endif
