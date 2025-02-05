#include <gmp.h>
#include <time.h>
#include <string>
#include "./ec/ec_multiply.h"
#include "./ec/ec_set.h"
#include "./ec/ec_gen_keys.h"
#include "./hash/sha256.h"

//using nondeterministic k as increasing structure increases potential attack vectors. there is no good reason to use deterministic k

struct signature_pair {
    mpz_t* residual;
    mpz_t* signature;

    signature_pair(mpz_t* res, mpz_t* sig){
        residual = res;
        signature = sig;
    }
};

signature_pair sign(mpz_t domain_params[6], key_pair kp, std::string message){
    std::string e = sha256(message);

    gmp_randstate_t st;
    gmp_randinit_default(st);
    
    mpz_t k;
    mpz_init2(k, 256);
    mpz_urandomm(k, st, domain_params[4]);

    mpz_t x;
    mpz_init2(x, 256);
    ec_multiply(x, domain_params[3], k, domain_params[0]);

    mpz_t r;
    mpz_init2(r, 256);
    mpz_mod(r, x, domain_params[4]);

    
}

bool verify(mpz_t domain_params[6], signature_pair sp, key_pair kp){
    return 0;
}
