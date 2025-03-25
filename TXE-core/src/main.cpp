#include "/workspaces/ecc/TXE-core/include/tx.h"
#include "/workspaces/ecc/TXE-core/include/block.h"
#include <iostream>
#include <iomanip>

std::string charArrayToHexString(const unsigned char* arr, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(arr[i]));
    }
    return oss.str();
}

int main(){
    block bloc;
    tx a(61);
    tx b(62);
    tx c(63);
    tx d(64);
    unsigned char res[64];
    bloc.tx_list = {a,b,c,d};
    bloc.create_merkle_root(res);
    std::cout << charArrayToHexString(res, 32);
    return 0;
}