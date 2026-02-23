#ifndef __BIGINT_H__
#define __BIGINT_H__

#include "ippcp.h"
#include <stdlib.h>
#include "uchar_vector.h"
typedef std::vector<unsigned char> bytes_t;

class BigInt{
public:
    IppsBigNumState* BN_;
    int size_; // size in IPP32U FORM;
    int cS_;

    void derive_from_8u(int size_32, const Ipp8u* data){
        size_ = size_32;
        ippsBigNumGetSize(size_32, &cS_);
        BN_=(IppsBigNumState*)new Ipp8u[cS_];
        ippsBigNumInit(size_32, BN_);
        if (data) ippsSetOctString_BN(data, size_32*4, BN_); // dS*4: data size in bytes;
    }

    BigInt(){}

    ~BigInt(){
        delete BN_;
    }

    BigInt(int size_32, const Ipp8u* data){ // data size: in ipp32u;
        derive_from_8u(size_32, data);
    }

    BigInt(int size_32, uchar_vector data){    
        // init an array; 
        Ipp8u* array = (Ipp8u*)malloc(data.size());
        data.copyToArray(array);
        
        size_ = size_32 / sizeof(Ipp32u);
        derive_from_8u(size_, array);

        // delete array;
        delete array;
    }

    BigInt(IppsBigNumState* data, int data_cS, int dS){
        cS_ = data_cS;
        size_ = dS;
        BN_ = data;
    }

    // Ipp8u* add_mod_BI(BigInt other, BigInt mod){ 
    //     int size_sum, size_sum_context, res_length;
    //     IppsBigNumState* SUM;
    //     Ipp8u* res;

    //     size_sum = IPP_MAX(sizeof(BN_), sizeof(other.BN_)); // size_sum = 8;
    //     ippsBigNumGetSize(size_sum+1, &size_sum_context);

    //     // init SUM;
    //     SUM = (IppsBigNumState*)malloc(size_sum_context); // sizeNUM: cS; 
    //     ippsBigNumInit(size_sum + 1, SUM);

    //     // operation
    //     ippsAdd_BN(BN_, other.BN_, SUM);
        
    //     res_length  = (size_sum + 1)*4;
    //     res = new Ipp8u[res_length];  

    //     ippsMod_BN(SUM, mod.BN_, SUM);

    //     // init res; 
    //     res_length  = (size_sum + 1)*4;
    //     ippsGetOctString_BN(res, res_length, SUM);

    //     delete SUM;
    //     return res;                
    // }

    int cmp_BI(BigInt other){
        Ipp32u res;
        ippsCmp_BN(BN_, other.BN_, &res);
        return res;
    }

    void print_BI() const{
        Ipp8u out_string[size_ * 4];

        ippsGetOctString_BN(out_string, size_*4, BN_);

        // for (int i=0; i<size_*4; i++){
        //     printf("%02x", out_string[i]);
        // }
        // printf("\n");
    }

};

#endif