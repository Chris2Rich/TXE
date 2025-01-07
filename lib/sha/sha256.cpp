#include <gmp.h>

void sha256(mpz_t res, mpz_t inp){
    mpz_t h0,h1,h2,h3,h4,h5,h6,h7;
    
    mpz_init_set_str(h0, "0x6a09e667", 16);
    mpz_init_set_str(h1, "0xbb67ae85", 16);
    mpz_init_set_str(h2, "0x3c6ef372", 16);
    mpz_init_set_str(h3, "0xa54ff53a", 16);
    mpz_init_set_str(h4, "0x510e527f", 16);
    mpz_init_set_str(h5, "0x9b05688c", 16);
    mpz_init_set_str(h6, "0x1f83d9ab", 16);
    mpz_init_set_str(h7, "0x5be0cd19", 16);
    
    mpz_t k[64];
    mpz_init_set_str(k[0], "0x428a2f98", 16);
    mpz_init_set_str(k[1], "0x71374491", 16);
    mpz_init_set_str(k[2], "0xb5c0fbcf", 16);
    mpz_init_set_str(k[3], "0xe9b5dba5", 16);
    mpz_init_set_str(k[4], "0x3956c25b", 16);
    mpz_init_set_str(k[5], "0x59f111f1", 16);
    mpz_init_set_str(k[6], "0x923f82a4", 16);
    mpz_init_set_str(k[7], "0xab1c5ed5", 16);
    
    mpz_init_set_str(k[8], "0xd807aa98", 16);
    mpz_init_set_str(k[9], "0x12835b01", 16);
    mpz_init_set_str(k[10], "0x243185be", 16);
    mpz_init_set_str(k[11], "0x550c7dc3", 16);
    mpz_init_set_str(k[12], "0x72be5d74", 16);
    mpz_init_set_str(k[13], "0x80deb1fe", 16);
    mpz_init_set_str(k[14], "0x9bdc06a7", 16);
    mpz_init_set_str(k[15], "0xc19bf174", 16);
    
    mpz_init_set_str(k[16], "0xe49b69c1", 16);
    mpz_init_set_str(k[17], "0xefbe4786", 16);
    mpz_init_set_str(k[18], "0x0fc19dc6", 16);
    mpz_init_set_str(k[19], "0x240ca1cc", 16);
    mpz_init_set_str(k[20], "0x2de92c6f", 16);
    mpz_init_set_str(k[21], "0x4a7484aa", 16);
    mpz_init_set_str(k[22], "0x5cb0a9dc", 16);
    mpz_init_set_str(k[23], "0x76f988da", 16);
    
    mpz_init_set_str(k[24], "0x983e5152", 16);
    mpz_init_set_str(k[25], "0xa831c66d", 16);
    mpz_init_set_str(k[26], "0xb00327c8", 16);
    mpz_init_set_str(k[27], "0xbf597fc7", 16);
    mpz_init_set_str(k[28], "0xc6e00bf3", 16);
    mpz_init_set_str(k[29], "0xd5a79147", 16);
    mpz_init_set_str(k[30], "0x06ca6351", 16);
    mpz_init_set_str(k[31], "0x14292967", 16);
    
    mpz_init_set_str(k[32], "0x27b70a85", 16);
    mpz_init_set_str(k[33], "0x2e1b2138", 16);
    mpz_init_set_str(k[34], "0x4d2c6dfc", 16);
    mpz_init_set_str(k[35], "0x53380d13", 16);
    mpz_init_set_str(k[36], "0x650a7354", 16);
    mpz_init_set_str(k[37], "0x766a0abb", 16);
    mpz_init_set_str(k[38], "0x81c2c92e", 16);
    mpz_init_set_str(k[39], "0x92722c85", 16);
    
    mpz_init_set_str(k[40], "0xa2bfe8a1", 16);
    mpz_init_set_str(k[41], "0xa81a664b", 16);
    mpz_init_set_str(k[42], "0xc24b8b70", 16);
    mpz_init_set_str(k[43], "0xc76c51a3", 16);
    mpz_init_set_str(k[44], "0xd192e819", 16);
    mpz_init_set_str(k[45], "0xd6990624", 16);
    mpz_init_set_str(k[46], "0xf40e3585", 16);
    mpz_init_set_str(k[47], "0x106aa070", 16);
    
    mpz_init_set_str(k[48], "0x19a4c116", 16);
    mpz_init_set_str(k[49], "0x1e376c08", 16);
    mpz_init_set_str(k[50], "0x2748774c", 16);
    mpz_init_set_str(k[51], "0x34b0bcb5", 16);
    mpz_init_set_str(k[52], "0x391c0cb3", 16);
    mpz_init_set_str(k[53], "0x4ed8aa4a", 16);
    mpz_init_set_str(k[54], "0x5b9cca4f", 16);
    mpz_init_set_str(k[55], "0x682e6ff3", 16);
    
    mpz_init_set_str(k[56], "0x748f82ee", 16);
    mpz_init_set_str(k[57], "0x78a5636f", 16);
    mpz_init_set_str(k[58], "0x84c87814", 16);
    mpz_init_set_str(k[59], "0x8cc70208", 16);
    mpz_init_set_str(k[60], "0x90befffa", 16);
    mpz_init_set_str(k[61], "0xa4506ceb", 16);
    mpz_init_set_str(k[62], "0xbef9a3f7", 16);
    mpz_init_set_str(k[63], "0xc67178f2", 16);
    
    mpz_setbit(inp, mpz_sizeinbase(inp, 2));
    int K = 0;
    
    while((mpz_sizeinbase(inp, 2) + 1 + K + 64) % 512 != 0){
        mpz_clrbit(inp, mpz_sizeinbase(inp, 2));
        K += 1;
    }
    
    mpz_t limbs[mpz_sizeinbase(inp, 2) / 512];
    
}