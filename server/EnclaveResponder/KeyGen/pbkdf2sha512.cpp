#include "pbkdf2sha512.h"
#include <math.h>
#include <algorithm>
#include <exception>
#include "ippcp.h"

PBKDF2SHA512::PBKDF2SHA512()
{

}

std::vector<unsigned char> PBKDF2SHA512::derive(const std::string & P, // password
                                                const std::string & S, // salt
                                                int c, int dkLen) { // 2048, 64
    std::vector<unsigned char> baos;
    // try {
        int hLen = 20;

        if (dkLen > ((pow(2, 32)) - 1) * hLen) {
            throw "derived key too long";
        }
        else {
            int l = (int)ceil((double)dkLen / (double)hLen);

            for (int i = 1; i <= l; i++) { // l is dklen / hlen = 64 / 20 = 4;
                std::vector<unsigned char> T = F(P, S, c, i); // F(passwd, salt, iteration, i) --> return 64 bits;
                baos.insert(baos.end(), T.begin(), T.end());
            }
        }
    // }
    // catch (const std::exception& ex) {
    //     std::cout << ex.what() << std::endl;
    //     throw ex;
    // }

    baos.resize(dkLen); // resize to dkLen;
    return baos;
}


std::vector<unsigned char> PBKDF2SHA512::F(const std::string & P,
                                           const std::string& /*S*/,
                                           int c, int/* i*/) {
    std::vector<unsigned char> U_LAST;
    std::vector<unsigned char> U_XOR(64,0);


    for (int j = 0; j < c; j++) {
        // CHMAC_SHA512 mac((unsigned char*)P.c_str(), P.length());
        if (j == 0) {
            ippsHMAC_Message(U_LAST.data(), U_LAST.size(), (unsigned char*)P.c_str(), P.length(), &U_XOR[0], 64, ippHashAlg_SHA512);
            // mac.Write(U_LAST.data(), U_LAST.size()).Finalize(&U_XOR[0]);
            U_LAST = U_XOR;
        }
        else {
            std::vector<unsigned char> baU(64,0); // baU: store result;
            // mac.Write(U_LAST.data(), U_LAST.size()).Finalize(&baU[0]);
            ippsHMAC_Message(U_LAST.data(), U_LAST.size(), (unsigned char*)P.c_str(), P.length(), &baU[0], 64, ippHashAlg_SHA512);

            for (size_t k = 0; k < U_XOR.size(); k++) {
                U_XOR[k] = (unsigned char)(U_XOR[k] ^ baU[k]); // U_XOR = U_XOR ^ baU;
            }

            U_LAST = baU;
        }
    }

    return U_XOR;
}
