#include <stdint.h>
#include <math.h>
#include <cstring>
#include "../../cryptopp/cryptlib.h"
#include "../../cryptopp/sha.h"

struct tx_in{
    unsigned char blob[256];
};

struct tx_out{
    uint64_t amount;
    unsigned char blob[256];
};

struct tx{
    unsigned char version;
    unsigned char id[64]; //generated from double hash of the data it contains
    
    tx_in* inputs;
    unsigned char input_n;

    tx_out* outputs;
    unsigned char output_n;

    const unsigned char* create_tx_id(){
        const unsigned char* res = (const unsigned char*)"Test"; 
        return res;
    }
};