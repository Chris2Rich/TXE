#include <gmp.h>
#include <time.h>
#include <vector>
#include "./ec_multiply.h"
#include "./ec_set.h"

struct key_pair{
    mpz_t* prvkey;
    mpz_t* pubkey;

    key_pair(mpz_t* prv, mpz_t* pub);
};

//keys are printed to output for storage by the user or to be piped into another command
key_pair ec_gen_keys(mpz_t domain_params[6]);