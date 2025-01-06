#include <iostream>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include "../lib/ec_multiply.h"
#include "../lib/ec_set.h"

//We work modulo p where p is a large prime number because otherwise we could have infinite points on the curve with numbers becoming too big
//p must be prime so that every point has a multiplicative inverse as all numbers modulo p (prime) have one
//Elliptic curves are defined by y^2 = x^3 + ax + b -> hence we store a and b.
//We pick G (the generator) in order to generate a cyclic subgroup such that the point (G,G)
//This subgroup is {G, 2G, 3G,... (n-1)G, O} where O is the point at infinity 
//We pick G so that n is a large prime number so that attacks that brute force such as Pollard Rho are ineffective as they have to look over n elements
//n must be prime so that the cyclic subgroup is of the correct size, otherwise, it will be the size of the smallest factor of n which can be insecure - there will be a k such that kG = O for k < n
//h (the cofactor) is defined by E(Fp) / n and if 1, simplifies operations and maximises security. If too large then G generates a small subgroup and the private key is not well protected by the ECDLP

//All of the domain parameters are public

void gen_priv_key(mpz_t res){
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

    // pass shared secret through hash function to destroy any structure

    mpz_set(res, QB);
}

int main(int argc, char** argv){
    std::cout << "test";
    return 0;
} 