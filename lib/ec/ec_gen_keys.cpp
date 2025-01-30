#include <gmp.h>
#include <time.h>
#include <vector>
#include "./ec_multiply.h"
#include "./ec_set.h"

struct key_pair{
    mpz_t* prvkey;
    mpz_t* pubkey;

    key_pair(mpz_t* prv, mpz_t* pub){
        prvkey = prv;
        pubkey = pub;
        return;
    }
};

//keys are printed to output for storage by the user or to be piped into another command
key_pair ec_gen_keys(mpz_t domain_params[6]){ 
    gmp_randstate_t st;
    gmp_randinit_default(st);
    
    mpz_t dA;
    mpz_init2(dA, 256);
    mpz_urandomm(dA, st, domain_params[4]); //selected private key
    
    mpz_t QA;
    mpz_init2(QA, 256);
    
    ec_multiply(QA, domain_params[3], dA, domain_params[0]); //generated public key

    return key_pair(&dA, &QA);
}