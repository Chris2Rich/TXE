#include <string>
#include <stdint.h>
#include <bitset>
#include "/src/tx/tx.cpp"

struct header {
    std::string id; //hash of previous block, uses sha512 so 512 bit output, once verified the block's tx data can be requested from validator
    std::string nonce; // for nonce space, initialized to 128 bits
    std::string merkel_root;
    std::bitset<512> difficulty; //proposed difficulty, verified by consensu
};

struct block {
    std::string id; //stored in db and ID is used for rapid indexing
    void* tx_list;
};

int main(){
    return 0;
}