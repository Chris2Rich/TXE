#include <stdint.h>
#include <math.h>
#include <cstring>
#include "../../cryptopp/cryptlib.h"
#include "../../cryptopp/sha.h"
#include <vector>

struct tx_in{
    unsigned char blob[256]; //whatever data is needed to unlock the coin
};

struct tx_out{
    uint64_t amount;
    unsigned char blob[256]; //the code that will be ran to unlock the coin in the future
};

struct tx{
    unsigned char version;
    unsigned char id[64]; //generated from double hash of the data it contains
    
    std::vector<tx_in> inputs;
    std::vector<tx_out> outputs;

    tx(unsigned char i){
        unsigned char v[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i};
        memcpy(id, v, 64);
    }

    const unsigned char* create_tx_id(){
        const unsigned char* res = (const unsigned char*)"Test"; 
        return res;
    }
};