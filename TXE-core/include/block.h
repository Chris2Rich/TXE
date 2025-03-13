#include <stdint.h>
#include "TXE-core/include/tx.h"
#include "TXE-core/include/sha512.h"
#include <math.h>
#include <cstring>
#include <vector>

struct header {
    unsigned int version; // if version changes, this allows for backwards compatability
    unsigned char id[64]; //hash of concatenation of ancestors' data - allows for unique ids with ancestors
    std::vector<unsigned char> ancestors; //concatenation of the ids of the ancestors a block has. 
    unsigned char nonce[64]; // for nonce space, this should be equal to the size of the domain of the hash function
    unsigned char merkel_root[64];
    uint32_t difficulty; //proposed difficulty, verified by consensus
};

struct block {
    unsigned char id[64]; //stored in db and ID is used for rapid indexing into b-tree
    std::vector<std::vector<unsigned char>> merkletree; //first level  in [0], 2nd level in [1,2] 3rd level in [3,4,5,6] etc 
    std::vector<tx> tx_list;

    //returns sha512 of the merkle root of the block(more random)
    void create_merkle_root(unsigned char* res) {}
};