#ifndef OUTPUT_HPP
#define OUTPUT_HPP

#ifndef HASH_HPP
#include "sha.h"
// #include "Utility_E2.h"
#endif

#include "EnclaveResponder_t.h" // ocall_printf
#include <stdio.h> // printf / vsnprintf
void printf(const char *fmt, ...);
int show_hash(hash *hash_val);

#endif