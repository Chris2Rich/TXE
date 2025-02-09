#include <cryptlib.h>
#include "xed25519.h"
#include "filters.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
 
#include <string>
#include <iostream>
#include <iomanip>
#include <exception>

#define USE_PIPELINE 1
int main(){
    CryptoPP::BlockingRng rand;
    rand.GenerateBlock(key.data(), key.size());
    rand.GenerateBlock(iv.data(), iv.size());

    return 0;
}