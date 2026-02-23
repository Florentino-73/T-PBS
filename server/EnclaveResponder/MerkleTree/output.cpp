#include "output.h"
// #include "Utility_E2.h"

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_printf(buf);
}

int show_hash(hash *hash_val){
    if (not hash_val){
        return 1; // not hash;
    }
    for (int i=0; i<SHA_LEN; i++){
    }
    return 0;
}