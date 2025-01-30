#include <gmp.h>
#include <time.h>
#include <string>
#include "./ec/ec_multiply.h"
#include "./ec/ec_set.h"
#include "./ec/ec_gen_keys.h"
#include "./hash/sha256.h"

//salted k - append hash of message to private key and hash again, then take logical and of a pseudorandom number x such that 1 <= x <= n-1.

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
    
}

bool verify(mpz_t domain_params[6], signature_pair sp, key_pair kp){
    return 0;
}
