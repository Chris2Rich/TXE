#include <iostream>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>

//We work modulo p where p is a large prime number because otherwise we could have infinite points on the curve with numbers becoming too big
//p must be prime so that every point has a multiplicative inverse as all numbers modulo p (prime) have one
//Elliptic curves are defined by y^2 = x^3 + ax + b -> hence we store a and b.
//We pick G (the generator) in order to generate a cyclic subgroup such that the point (G,G)
//This subgroup is {G, 2G, 3G,... (n-1)G, O} where O is the point at infinity 
//We pick G so that n is a large prime number so that attacks that brute force such as Pollard Rho are ineffective as they have to look over n elements
//n must be prime so that the cyclic subgroup is of the correct size, otherwise, it will be the size of the smallest factor of n which can be insecure - there will be a k such that kG = O for k < n
//h (the cofactor) is defined by E(Fp) / n and if 1, simplifies operations and maximises security. If too large then G generates a small subgroup and the private key is not well protected by the ECDLP

//All of the domain parameters are public

//secp256k1 - also used in bitcoin - this has KNOWN vulnerabilities
//{p,a,b,G,n,h}
mpz_t domain_params[6];

//helper functions
void ec_multiply(mpz_t res, mpz_t G, mpz_t d);

int main(int argc, char** argv){
    for(int i = 0; i < 6; i++){
        mpz_init2(domain_params[i], 256);
    }
    
    mpz_set_str(domain_params[0], "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_set_str(domain_params[1], "0x0", 16);
    mpz_set_str(domain_params[2], "0x7", 16);
    mpz_set_str(domain_params[3], "0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_set_str(domain_params[4], "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036414", 16);
    mpz_set_str(domain_params[5], "0x1", 16);
    
    //10^76 possible values, and over the entire field!
    
    gmp_randstate_t st;
    gmp_randinit_default(st);
    
    mpz_t dA; //Secret key chosen at random
    mpz_init2(dA, 256);
    mpz_urandomm(dA, st, domain_params[4]);
    
    mpz_t QA;
    mpz_init2(QA, 256);
    
    ec_multiply(QA, domain_params[3], dA); //Alice's public key
    
    mpz_t QB; //Bob's public key;
    mpz_init2(QB, 256);
    
    ec_multiply(QB, QB, dA); //Derives shared secret as dA * QB = dA * dB * G = dB * dA * G = dB * QA as multiplication is commutative under modulo and on the points on an elliptic curve
    
    return 0;
}

//Use "constant" time double and add to resist timing attacks - achieves "constant" time for all inputs by boolean arithmetic rather than branching
//This is not constant time as the algorithm iterates over every element therefore it has ~O(log_2(n)) time complexity however as this is fixed, it is "constant" for all inputs
void ec_multiply(mpz_t res, mpz_t G, mpz_t d){
    int i = 254;
    mpz_set(res, domain_params[0]);
    
    mpz_t flag;
    mpz_init2(flag, 256);
    
    while(i >= 0){
        mpz_set(flag, domain_params[0]);
        mpz_mul_si(res, res, 2);
        mpz_mul_si(flag, flag, mpz_tstbit(G, i));
        mpz_add(res, res, flag); //Boolean arithmetic
        i -= 1;
    }
    
    mpz_clear(flag);
    return;
}