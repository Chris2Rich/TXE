#include <stdint.h>
#include <vector>
#include <bitset>
#include <algorithm>
#include <iostream>

// how to increase performance -- reduce allocations, switch to using 32bit
// integers for inner loop instead of arbitrary precision integers: further
// research needed

// convert string to binary string
std::vector<bool> stobin(std::vector<unsigned char> inp){
  std::vector<bool> res;
  for (int i = 0; i < inp.size(); i++) {
    std::bitset<8> bits(inp[i]);
    for (int j = 7; j >= 0; j--) {
      res.push_back(bits[j]);
    }
  }
  return res;
}

// simplifies to single instruction
uint32_t rotr(const uint32_t x, int n) {
  const unsigned int mask = 8 * 32 - 1;
  n &= mask;
  return (x >> n) | (x << (-n & mask));
}

uint32_t ls0(uint32_t x) {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint32_t ls1(uint32_t x) {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

std::vector<bool> sha256(std::vector<unsigned char> inp) {
  uint32_t h0 = 0x6a09e667;
  uint32_t h1 = 0xbb67ae85;
  uint32_t h2 = 0x3c6ef372;
  uint32_t h3 = 0xa54ff53a;
  uint32_t h4 = 0x510e527f;
  uint32_t h5 = 0x9b05688c;
  uint32_t h6 = 0x1f83d9ab;
  uint32_t h7 = 0x5be0cd19;

  uint32_t K[64] {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  std::vector<bool> bin = stobin(inp);
  int origi = bin.size();
  std::bitset<64> l(bin.size());
  bin.push_back(true);
  int k = 0;
  while((origi + k + 1) % 512 != 448){
    bin.push_back(false);
    k++;
  }
  for(int i = 63; i >= 0; i--){
    bin.push_back(l[i]);
  }
  
  std::vector<std::vector<bool>> blocks512_b;
  for(int i = 0; i < bin.size() / 512; i++){
    std::vector<bool> tmp;
    for(int j = 0; j < 512; j++){
      tmp.push_back(bin[512*i + j]);
    }
    blocks512_b.push_back(tmp);
  }

  std::vector<std::vector<uint32_t>> M;
  for(int i = 0; i < blocks512_b.size(); i++){
    std::vector<uint32_t> vec;
    for(int j = 0; j < 16; j++){
      uint32_t tmp = 0;
      for(int k = 0; k < 32; k++){
        tmp += blocks512_b[i][j*32 + k] << (31 - k);
      }
      std::cout << tmp << "\n";
      vec.push_back(tmp);
    }
    M.push_back(vec);
  }

  return bin;
}

int main() {
  std::vector<unsigned char> a {1};
  sha256(a);
  return 0;
}