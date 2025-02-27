#include <stdint.h>
#include "../tx/tx.cpp"
#include <math.h>
#include <cstring>
#include "../../cryptopp/cryptlib.h"
#include "../../cryptopp/sha.h"

struct header {
    unsigned char version; // if version changes, this allows for backwards compatability
    unsigned char prevhash[64]; //hash of concatenation of ancestors' data - allows for unique ids with ancestors
    unsigned char ancestors[256]; //concatenation of the ids of the 4 ancestors a block can have. if only 1 true ancestor then use genesis block. 
    unsigned char nonce[64]; // for nonce space, this should be equal to the size of the domain of the hash function
    unsigned char merkel_root[64];
    uint32_t difficulty; //proposed difficulty, verified by consensus
};

struct block {
    unsigned char id[64]; //stored in db and ID is used for rapid indexing into b-tree
    unsigned int tx_count;
    tx tx_list[];

    //returns sha512 of the merkle root of the block(more random)
    void create_merkle_root(unsigned char* res){
        CryptoPP::SHA512 hash;
        unsigned char digest[64];

        unsigned const char* nodes[(unsigned int)pow(2, ceil(log2(tx_count)))]; // array of pointers to strings
        for(unsigned int i = 0; i < pow(2, ceil(log2(tx_count))); i++){
            if(i < tx_count){
                hash.Update(tx_list[i].id, strlen(reinterpret_cast<const char*>(tx_list[i].id)));
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
                hash.Update(level[0], 1024);
                hash.Final(digest);
                res = digest;
                return;
            }
        }
        res = nullptr;
        return;
    };
};

int main(){
    return 0;
}