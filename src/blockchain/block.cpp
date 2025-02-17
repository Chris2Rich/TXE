#include <stdint.h>
#include "../tx/tx.cpp"

struct header {
    unsigned char version; // if version changes, this allows for backwards compatability
    unsigned char id[64]; //hash of previous block, uses sha512 so 512 bit output, once verified the block's tx data can be requested from validator, as the model of the ledger is NOT a blockchain, multiple blocks can point to a single ancestor, therefore they will need to have different nonces, regular model of blockchain consensus with MCW (most cumulative work) will be used to determine which branch has precedence IF they use the same nonce, otherwise there is limited potential for future id collision.
    unsigned char nonce[64]; // for nonce space, this should be equal to the size of the domain of the hash function
    unsigned char merkel_root[64];
    uint32_t difficulty; //proposed difficulty, verified by consensus
};

struct block {
    unsigned char id[64]; //stored in db and ID is used for rapid indexing into b-tree
    tx tx_list[];

    unsigned char* create_merkel(){
        return nullptr;
    };
};

int main(){
    return 0;
}