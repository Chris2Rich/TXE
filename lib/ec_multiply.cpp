#include <gmp.h>

//Uses "constant" time double and add to resist timing attacks - achieves "constant" time for all inputs by boolean arithmetic rather than branching
//This is not constant time as the algorithm iterates over every element therefore it has ~O(log_2(n)) time complexity however as this is fixed, it is "constant" for all inputs

//O(n) - pseudoconstant time
void ec_multiply(mpz_t res, mpz_t G, mpz_t d, mpz_t p){
    int i = 254;
    mpz_set(res, p);
    
    mpz_t flag;
    mpz_init2(flag, 256);
    
    while(i >= 0){
        mpz_set(flag, p);
        mpz_mul_si(res, res, 2);
        mpz_mul_si(flag, flag, mpz_tstbit(G, i));
        mpz_add(res, res, flag); //Boolean arithmetic
        i -= 1;
    }
    
    mpz_clear(flag);
    return;
}