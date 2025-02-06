#include <gmp.h>

//secp256k1 - also used in bitcoin - uses compressed generator point to reduce attack surface area when dealing with modular arithmetic based timing attacks
//{p,a,b,G,n,h}
void secp256k1(mpz_t res[6]){        
        mpz_init_set_str(res[0], "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        mpz_init_set_str(res[1], "0", 16);
        mpz_init_set_str(res[2], "7", 16);
        mpz_init_set_str(res[3], "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        mpz_init_set_str(res[4], "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036414", 16);
        mpz_init_set_str(res[5], "1", 16);
    return;
}