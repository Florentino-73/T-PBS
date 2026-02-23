#include "mnemoniccode.h"
#include "pbkdf2sha512.h"

MnemonicCode::MnemonicCode()
{

}

std::vector<unsigned char> MnemonicCode::toSeed(std::string pass,
                                                const std::string &passphrase) {

    const std::string& salt = "mnemonic" + passphrase;
    return PBKDF2SHA512::derive(pass, salt, PBKDF2_ROUNDS, seedSize); // PBKDF2_ROUNDS: 2048, seedSize: 64; -----> derive a seed key;
}
