#include <gmp.h>
#include <time.h>
#include "./ec/ec_multiply.h"
#include "./ec/ec_set.h"

void gen_secret(mpz_t res){
    mpz_t domain_params[6];
    
    gmp_randstate_t st;
    gmp_randinit_default(st);
    
    mpz_t dA; //Secret key chosen at random
    mpz_init2(dA, 256);
    mpz_urandomm(dA, st, domain_params[4]);
    
    mpz_t QA;
    mpz_init2(QA, 256);
    
    ec_multiply(QA, domain_params[3], dA, domain_params[0]); //Alice's public key
    
    mpz_t QB; //Bob's public key;
    mpz_init2(QB, 256);
    
    ec_multiply(QB, QB, dA, domain_params[0]); //Derives shared secret as dA * QB = dA * dB * G = dB * dA * G = dB * QA as multiplication is commutative under modulo and on the points on an elliptic curve

    mpz_set(res, QB); //Should be passed through KDF for security
}
