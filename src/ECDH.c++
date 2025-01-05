#include <iostream>

//We work modulo p where p is a large prime number because otherwise we could have infinite points on the curve with numbers becoming too big
//P must be prime so that every point has a multiplicative inverse as all numbers modulo p (prime) have one
//Elliptic curves are defined by y^2 = x^3 + ax + b -> hence we store a and b.
//We pick G (the generator) in order to generate a cyclic subgroup
//This subgroup is {G, 2G, 3G,... (n-1)G, O} where O is the point at infinity
//We pick G so that n is a large prime number so that attacks that brute force such as Pollard Rho are ineffective as they have to look over n elements
//n must be prime so that the cyclic subgroup is of the correct size, otherwise, it will be the size of the smallest factor of n which can be insecure - there will be a k such that kG = O for k < n
//h (the cofactor) is defined by E(Fp) / n and if 1, simplifies operations and maximises security. If too large then G generates a small subgroup and the private key is not well protected by the ECDLP

//All of the domain parameters are public
//{p,a,b,G,n,h}
int* domain_params = {}; 

int main(int argc, char** argv){
    
    return 0;
}