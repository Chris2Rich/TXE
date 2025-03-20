#ifndef _SHA512_H

#define _SHA512_H

#include <openssl/sha.h>
#include <vector>
#include <iostream>

std::vector<unsigned char> hash512(unsigned char* v, size_t n);

std::vector<unsigned char> hash512(std::vector<unsigned char> v);

#endif // _SHA512_H