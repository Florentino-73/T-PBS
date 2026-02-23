#include "sgx_eid.h"
#include "stdlib.h"
#include "string.h"

#include "error_codes.h"

#include "Utility_E1.h"

#ifdef _LOG
#include "EnclaveInitiator_t.h"
#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>     /* va_list, va_start, va_end */
#else
// For enclave environment, we need to declare snprintf
extern "C" int snprintf(char *str, size_t size, const char *format, ...);
#endif


#ifdef _LOG
extern "C" void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_printf(buf);
}
#endif 

void PRINT_BYTE_ARRAY(void *mem, uint32_t len)
{
    (void)mem;
    (void)len;
    return;
}


void show_ut(const uint8_t *var, size_t length, const char *fmt){
    (void)var;    // suppress unused parameter warning
    (void)length; // suppress unused parameter warning
    (void)fmt;    // suppress unused parameter warning
}


const uint32_t filename_size = 100;
uint32_t get_encrypted_filename(uint32_t data_id, char **new_filename){
    char *filename = (char *)malloc(filename_size);
    memset(filename, 0, filename_size);
    snprintf(filename, filename_size, "../test_data/gwas_encrypted/%08x.gwas", data_id);
    *new_filename = filename;
    return 0;
}
