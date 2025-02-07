#include <gmp.h>

bool ec_verify(mpz_t inp, mpz_t domain_params[6]){
    mpz_mod(inp, inp, domain_params[4]);
    return false;
}