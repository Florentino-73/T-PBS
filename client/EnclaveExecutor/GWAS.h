#ifndef GWAS_H_
#define GWAS_H_

#include "datatypes.h"
#include "error_codes.h"
#include "Utility_E3.h"



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <cmath>

#include <iostream>
#include <climits>
#include <cassert>

#include "sgx_trts.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "sgx_utils.h"
#include "sgx_ecp_types.h"
#include "sgx_tprotected_fs.h"

#define SMALLISH_EPSILON 0.00000000003
#define SMALL_EPSILON 0.0000000000001
// This helps us avoid premature floating point overflow.
#define EXACT_TEST_BIAS 0.00000000000000000000000010339757656912845935892608650874535669572651386260986328125

typedef struct element {
    uint32_t counters[4];
    uint8_t data[276];
}element;

uint32_t add_snp(uint8_t *content, uint32_t content_len);
uint32_t cal_hwe(uint32_t rs_id, uint8_t *hweResult);
uint32_t cal_fet(uint32_t rs_id, uint8_t* fetResult);
uint32_t cal_catt(uint32_t rs_id, uint8_t* cattResult);
uint32_t cal_ld(uint32_t rs_id_1, uint32_t rs_id_2, uint8_t* ldResult);

double fisher23(uint32_t m11, uint32_t m12, uint32_t m13, uint32_t m21, uint32_t m22, uint32_t m23, uint32_t midp);
int32_t fisher23_tailsum(double* base_probp, double* saved12p, double* saved13p, double* saved22p, double* saved23p, double *totalp, uint32_t* tie_ctp, uint32_t right_side);

#endif