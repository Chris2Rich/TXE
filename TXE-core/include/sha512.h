#ifndef _SHA512_H
#define _SHA512_H

#include <openssl/sha.h>
#include <vector>
#include <iostream>

// Low-level SHA-512, operates on arrays
std::vector<unsigned char> hash512(unsigned char* v, size_t n) {
    SHA512_CTX ctx;
    unsigned char buffer[SHA512_DIGEST_LENGTH];

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, v, n);
    SHA512_Final(buffer, &ctx);

    std::vector<unsigned char> res;
    res.insert(res.end(), buffer, buffer + SHA512_DIGEST_LENGTH);
    return res;
}

// Low-level SHA-512, operates on vectors
std::vector<unsigned char> hash512(const std::vector<unsigned char>& v) {
    SHA512_CTX ctx;
    unsigned char buffer[SHA512_DIGEST_LENGTH];

    SHA512_Init(&ctx);
    if (!v.empty()) {
        SHA512_Update(&ctx, &v[0], v.size());
    }
    SHA512_Final(buffer, &ctx);

    std::vector<unsigned char> res;
    res.insert(res.end(), buffer, buffer + SHA512_DIGEST_LENGTH);
    return res;
}

#endif // _SHA512_H