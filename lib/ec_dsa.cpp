#include <gmp.h>
#include <time.h>
#include <string>
#include "./ec/ec_multiply.h"
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

    mpz_t z,k,x,r,s, tmp;
    mpz_init_set_str(z, sha256(message), 16);
    mpz_init2(k, 256);
    mpz_init2(x, 256);
    mpz_init2(r, 256);
    mpz_init2(s, 256);
    mpz_init2(tmp, 256);

    secure:

    gmp_randstate_t st;
    gmp_randinit_default(st);
    
    mpz_urandomm(k, st, domain_params[4]);

    ec_multiply(x, domain_params[3], k, domain_params[0]);


    mpz_mod(r, x, domain_params[4]);
    
    if(mpz_cmp_ui (r,0) == 0){
        goto secure;
    }

    mpz_invert(k, k, domain_params[4]);
    mpz_mul(tmp, r, *kp.prvkey);
    mpz_add(tmp, tmp, z);
    mpz_mul(s, k, tmp);

    if(mpz_cmp_ui (s,0) == 0){
        goto secure;
    }

    mpz_clear(z);
    mpz_clear(k);
    mpz_clear(x);
    mpz_clear(tmp);

    return signature_pair(&r, &s);
}

bool verify(mpz_t domain_params[6], signature_pair sp, key_pair kp){
    return 0;
}
 