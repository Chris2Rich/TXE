#ifndef _SHA512_H

#define _SHA512_H

#include <openssl/sha.h>
#include <vector>
#include <iostream>

//low level sha512, operates on arrays
std::vector<unsigned char> hash512(unsigned char* v, size_t n){
    SHA512_CTX ctx;
    unsigned char buffer[64];
    
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, v, n);
    SHA512_Final(buffer, &ctx);
    
    std::vector<unsigned char> res;
    res.insert(res.end(), std::begin(buffer), std::end(buffer));
    return res;
}

//low level sha512, operates on vectors
std::vector<unsigned char> hash512(std::vector<unsigned char> v){
    SHA512_CTX ctx;
    unsigned char buffer[64];
    
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, &v[0], v.size());
    SHA512_Final(buffer, &ctx);
    
    std::vector<unsigned char> res;
    res.insert(res.end(), std::begin(buffer), std::end(buffer));
    return res;
}
#endif // _SHA512_H