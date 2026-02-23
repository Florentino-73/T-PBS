#ifndef MNEMONICCODE_H
#define MNEMONICCODE_H

#include <list>
#include <vector>
#include <iostream>

class MnemonicCode
{
public:
    MnemonicCode();

    static std::vector<unsigned char> toSeed(std::string pass,
                                      const std::string &passphrase);

    static const int seedSize = 64;

private:
    static const int PBKDF2_ROUNDS = 2048;
};

#endif // MNEMONICCODE_H
