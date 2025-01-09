#include <gmp.h>
#include <math.h>
#define ulli unsigned long long int //Used for convenience

//Only works correcly when n is a power of 2
void split(mpz_t res[], mpz_t inp, ulli n) {
	ulli size = mpz_sizeinbase(inp, 2) / n;
	mpz_t mask;
	mpz_init_set_ui(mask, 2);
	mpz_pow_ui(mask, mask, n+1);
	mpz_sub_ui(mask, mask, 1);

	for(ulli i = 0; i < size; i++) {
		mpz_t temp;
		mpz_init_set(temp, inp);
		mpz_tdiv_q_2exp(temp, temp, n*i);
		mpz_and(temp, temp, mask);
		mpz_set(res[i], temp);

		mpz_clear(temp);
	}

	mpz_clear(mask);
	return;
}


void r_rotate(mpz_t res, mpz_t inp, ulli n) {
	mpz_t wrap, temp, mask, mask2, shifter;
	mpz_init(wrap);
	mpz_init_set(temp, inp);
	mpz_init_set_ui(mask, 2);
	mpz_init_set_ui(mask2, 2);
	mpz_init_set_ui(shifter, 2);

	mpz_pow_ui(mask, mask, n+1);
	mpz_sub_ui(mask, mask, 1);

	mpz_and(wrap, mask, temp); //take n smallest bits as wrap
	mpz_tdiv_q_2exp(temp, temp, n); //divide by 2^n

	mpz_pow_ui(shifter, shifter, mpz_sizeinbase(temp, 2)); //shifter = 2^(n-len(wrap))
	mpz_mul(wrap, wrap, shifter); //multiply wrap by shifter

	mpz_add(temp, wrap, temp); //add values together

  mpz_pow_ui(mask2, mask2, mpz_sizeinbase(inp, 2));
  mpz_sub_ui(mask2, mask2, 1);
	mpz_and(res, temp, mask2); //remove residuals

	mpz_clear(wrap);
	mpz_clear(temp);
	mpz_clear(mask2);
	mpz_clear(mask);
	mpz_clear(shifter);
	return;
}

void sha256(mpz_t res, mpz_t inp) {
	mpz_t h[8];
	mpz_t k[64];

	for(int i = 0; i < 8; i++) {
		mpz_init(h[i]);
	}

	for(int i = 0; i < 64; i++) {
		mpz_init(k[i]);
	}

	mpz_set_str(h[0], "6a09e667", 16);
	mpz_set_str(h[1], "bb67ae85", 16);
	mpz_set_str(h[2], "3c6ef372", 16);
	mpz_set_str(h[3], "a54ff53a", 16);
	mpz_set_str(h[4], "510e527f", 16);
	mpz_set_str(h[5], "9b05688c", 16);
	mpz_set_str(h[6], "1f83d9ab", 16);
	mpz_set_str(h[7], "5be0cd19", 16);

	mpz_set_str(k[0], "428a2f98", 16);
	mpz_set_str(k[1], "71374491", 16);
	mpz_set_str(k[2], "b5c0fbcf", 16);
	mpz_set_str(k[3], "e9b5dba5", 16);
	mpz_set_str(k[4], "3956c25b", 16);
	mpz_set_str(k[5], "59f111f1", 16);
	mpz_set_str(k[6], "923f82a4", 16);
	mpz_set_str(k[7], "ab1c5ed5", 16);

	mpz_set_str(k[8], "d807aa98", 16);
	mpz_set_str(k[9], "12835b01", 16);
	mpz_set_str(k[10], "243185be", 16);
	mpz_set_str(k[11], "550c7dc3", 16);
	mpz_set_str(k[12], "72be5d74", 16);
	mpz_set_str(k[13], "80deb1fe", 16);
	mpz_set_str(k[14], "9bdc06a7", 16);
	mpz_set_str(k[15], "c19bf174", 16);

	mpz_set_str(k[16], "e49b69c1", 16);
	mpz_set_str(k[17], "efbe4786", 16);
	mpz_set_str(k[18], "0fc19dc6", 16);
	mpz_set_str(k[19], "240ca1cc", 16);
	mpz_set_str(k[20], "2de92c6f", 16);
	mpz_set_str(k[21], "4a7484aa", 16);
	mpz_set_str(k[22], "5cb0a9dc", 16);
	mpz_set_str(k[23], "76f988da", 16);

	mpz_set_str(k[24], "983e5152", 16);
	mpz_set_str(k[25], "a831c66d", 16);
	mpz_set_str(k[26], "b00327c8", 16);
	mpz_set_str(k[27], "bf597fc7", 16);
	mpz_set_str(k[28], "c6e00bf3", 16);
	mpz_set_str(k[29], "d5a79147", 16);
	mpz_set_str(k[30], "06ca6351", 16);
	mpz_set_str(k[31], "14292967", 16);

	mpz_set_str(k[32], "27b70a85", 16);
	mpz_set_str(k[33], "2e1b2138", 16);
	mpz_set_str(k[34], "4d2c6dfc", 16);
	mpz_set_str(k[35], "53380d13", 16);
	mpz_set_str(k[36], "650a7354", 16);
	mpz_set_str(k[37], "766a0abb", 16);
	mpz_set_str(k[38], "81c2c92e", 16);
	mpz_set_str(k[39], "92722c85", 16);

	mpz_set_str(k[40], "a2bfe8a1", 16);
	mpz_set_str(k[41], "a81a664b", 16);
	mpz_set_str(k[42], "c24b8b70", 16);
	mpz_set_str(k[43], "c76c51a3", 16);
	mpz_set_str(k[44], "d192e819", 16);
	mpz_set_str(k[45], "d6990624", 16);
	mpz_set_str(k[46], "f40e3585", 16);
	mpz_set_str(k[47], "106aa070", 16);

	mpz_set_str(k[48], "19a4c116", 16);
	mpz_set_str(k[49], "1e376c08", 16);
	mpz_set_str(k[50], "2748774c", 16);
	mpz_set_str(k[51], "34b0bcb5", 16);
	mpz_set_str(k[52], "391c0cb3", 16);
	mpz_set_str(k[53], "4ed8aa4a", 16);
	mpz_set_str(k[54], "5b9cca4f", 16);
	mpz_set_str(k[55], "682e6ff3", 16);

	mpz_set_str(k[56], "748f82ee", 16);
	mpz_set_str(k[57], "78a5636f", 16);
	mpz_set_str(k[58], "84c87814", 16);
	mpz_set_str(k[59], "8cc70208", 16);
	mpz_set_str(k[60], "90befffa", 16);
	mpz_set_str(k[61], "a4506ceb", 16);
	mpz_set_str(k[62], "bef9a3f7", 16);
	mpz_set_str(k[63], "c67178f2", 16);

	for(int i = 0; i < 8; i++) {
		mpz_clear(h[i]);
	}

	for(int i = 0; i < 64; i++) {
		mpz_clear(k[i]);
	}
}

int main() {
	mpz_t a;
	mpz_init_set_str(a, "FFAABBCCCCAABBCC", 16);

	mpz_t res[4];
	for(int i = 0; i < 4; i++) {
		mpz_init(res[i]);
	}

	split(res, a, 32);
	r_rotate(res[1], res[1], 7);
	for(int i = 0; i < 4; i++) {
		gmp_printf("%#Zx\n", res[i]);
	}

	return 0;
}
