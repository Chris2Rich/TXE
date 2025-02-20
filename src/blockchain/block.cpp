#include <stdint.h>
#include "../tx/tx.cpp"
#include <math.h>
#include <cstring>
#include "../../cryptopp/cryptlib.h"
#include "../../cryptopp/sha.h"

struct header {
    unsigned char version; // if version changes, this allows for backwards compatability
    unsigned char id[64]; //hash of previous block, uses sha512 so 512 bit output, once verified the block's tx data can be requested from validator, as the model of the ledger is NOT a blockchain, multiple blocks can point to a single ancestor, therefore they will need to have different nonces, regular model of blockchain consensus with MCW (most cumulative work) will be used to determine which branch has precedence IF they use the same nonce, otherwise there is limited potential for future id collision.
    unsigned char nonce[64]; // for nonce space, this should be equal to the size of the domain of the hash function
    unsigned char merkel_root[64];
    uint32_t difficulty; //proposed difficulty, verified by consensus
};

struct block {
    unsigned char id[64]; //stored in db and ID is used for rapid indexing into b-tree
    unsigned int tx_count;
    tx tx_list[];

    unsigned const char* create_merkle_root(){
        CryptoPP::SHA512 hash;
        unsigned char digest[64];

        unsigned const char* nodes[(unsigned int)pow(2, ceil(log2(tx_count)))]; // array of pointers to strings
        for(unsigned int i = 0; i < pow(2, ceil(log2(tx_count))); i++){
            if(i < tx_count){
                hash.Update(tx_list[i].stringify(), strlen(reinterpret_cast<const char*>(tx_list[i].stringify())));
                hash.Final(digest);
                nodes[i] = digest;
            } else {
                hash.Update((const unsigned char*)"0", 1);
                hash.Final(digest);
                nodes[i] = digest;
            }
        }
        unsigned const char** prev = nodes;
        unsigned int height = (unsigned int)(ceil(log2(tx_count))) - 1;
        while(height >= 0){
            unsigned const char* level[(unsigned int)pow(2, (unsigned int)(ceil(log2(tx_count))) - 1)];
            for(unsigned int i = 0; i < pow(2, (unsigned int)(ceil(log2(tx_count))) - 2); i++){
                unsigned char concat[128];
                memcpy(concat, prev[i*2], 512);
                memcpy(concat + 64, prev[(i*2) + 1], 512);
                hash.Update(concat, 1024);
                hash.Final(digest);
                level[i] = digest;
            }
            prev = level;
            height -= 1;

            if(height == 0){
                return level[0];
            }
        }
        return nullptr;
    };
};

int main(){
    return 0;
}