#include <gmp.h>

// how to increase performance -- reduce allocations, switch to using 32bit
// integers for inner loop instead of arbitrary precision integers: further
// research needed

#define uint64_t unsigned long long
// Only works correcly when n is a power of 2
void split(mpz_t res[], mpz_t inp, uint64_t n) {
  uint64_t size = mpz_sizeinbase(inp, 2) / n;
  mpz_t mask, temp;
  mpz_init_set_ui(mask, 2);
  mpz_pow_ui(mask, mask, n + 1);
  mpz_sub_ui(mask, mask, 1);
  mpz_init(temp);

  for (uint64_t i = 0; i < size; i++) {
    mpz_set(temp, inp);
    mpz_tdiv_q_2exp(temp, temp, n * i);
    mpz_and(temp, temp, mask);
    mpz_set(res[i], temp);
  }

  mpz_clear(temp);
  mpz_clear(mask);
  return;
}

// replace with uint for speed (using arbitrary precision is pointless with
// 32bit words)
void r_rotate(mpz_t res, mpz_t inp, uint64_t n) {
  mpz_t wrap, temp, mask, mask2, shifter;
  mpz_init(wrap);
  mpz_init_set(temp, inp);
  mpz_init_set_ui(mask, 2);
  mpz_init_set_ui(mask2, 2);
  mpz_init_set_ui(shifter, 2);

  mpz_pow_ui(mask, mask, n + 1);
  mpz_sub_ui(mask, mask, 1);

  mpz_and(wrap, mask, temp);      // take n smallest bits as wrap
  mpz_tdiv_q_2exp(temp, temp, n); // divide by 2^n

  mpz_pow_ui(shifter, shifter,
             mpz_sizeinbase(temp, 2)); // shifter = 2^(n-len(wrap))
  mpz_mul(wrap, wrap, shifter);        // multiply wrap by shifter

  mpz_add(temp, wrap, temp); // add values together

  mpz_pow_ui(mask2, mask2, mpz_sizeinbase(inp, 2));
  mpz_sub_ui(mask2, mask2, 1);
  mpz_and(res, temp, mask2); // remove residuals

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

  for (int i = 0; i < 8; i++) {
    mpz_init(h[i]);
  }

  for (int i = 0; i < 64; i++) {
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

  mpz_t blocks[mpz_sizeinbase(inp, 2) / 512];

  for (int i = 0; i < mpz_sizeinbase(inp, 2) / 512; i++) {
    mpz_init(blocks[i]);
  }

  split(blocks, inp, 512);

  mpz_t msa[64];
  for (int i = 0; i < 64; i++) {
    mpz_init(msa[i]);
  }

  mpz_t s0_temp[3];
  mpz_t s1_temp[3];

  for (int i = 0; i < 3; i++) {
    mpz_init(s0_temp[i]);
    mpz_init(s1_temp[i]);
  }

  mpz_t a, b, c, d, e, f, g, h_, ch[2], temp1, temp2, maj[3];
  mpz_init(a);
  mpz_init(b);
  mpz_init(c);
  mpz_init(d);
  mpz_init(e);
  mpz_init(f);
  mpz_init(g);
  mpz_init(h_);
  for (int i = 0; i < 2; i++) {
    mpz_init(ch[i]);
  }
  mpz_init(temp1);
  mpz_init(temp2);
  for (int i = 0; i < 3; i++) {
    mpz_init(maj[i]);
  }

  // avoid allocating inside main loop
  for (int i = 0; i < mpz_sizeinbase(inp, 2) / 512; i++) {
    split(msa, blocks[i], 32);

    for (int i = 16; i < 64; i++) {
      // s0_temp[0] represents s0
      r_rotate(s0_temp[0], msa[i - 15], 7);
      r_rotate(s0_temp[1], msa[i - 15], 18);
      mpz_tdiv_q_2exp(s0_temp[2], msa[i - 15], 3);
      mpz_xor(s0_temp[0], s0_temp[0], s0_temp[1]);
      mpz_xor(s0_temp[0], s0_temp[0], s0_temp[2]);

      // s1_temp[0] represents s1
      r_rotate(s1_temp[0], msa[i - 2], 17);
      r_rotate(s1_temp[1], msa[i - 2], 19);
      mpz_tdiv_q_2exp(s1_temp[2], msa[i - 2], 10);
      mpz_xor(s1_temp[0], s1_temp[0], s1_temp[1]);
      mpz_xor(s1_temp[0], s1_temp[0], s1_temp[2]);

      // sum w[i-16], s0, w[i-7], s1 into s0 (AKA s0_temp[0])
      mpz_add(s0_temp[0], s0_temp[0], msa[i - 16]);
      mpz_add(s0_temp[0], s0_temp[0], msa[i - 7]);
      mpz_add(s0_temp[0], s0_temp[0], s1_temp[0]);
      mpz_mod_ui(s0_temp[0], s0_temp[0], 0x100000000);

      mpz_set(msa[i], s0_temp[0]);
    }

    mpz_set(a, h[0]);
    mpz_set(b, h[1]);
    mpz_set(c, h[2]);
    mpz_set(d, h[3]);
    mpz_set(e, h[4]);
    mpz_set(f, h[5]);
    mpz_set(g, h[6]);
    mpz_set(h_, h[7]);

    // reuse s0_temp and s1_temp for S0/1

    for (int i = 0; i < 64; i++) {
      r_rotate(s1_temp[0], e, 6);
      r_rotate(s1_temp[0], e, 11);
      r_rotate(s1_temp[0], e, 25);
      mpz_xor(s1_temp[0], s1_temp[0], s1_temp[1]);
      mpz_xor(s1_temp[0], s1_temp[0], s1_temp[2]);

      mpz_and(ch[0], e, f);
      mpz_com(ch[1], e);
      mpz_and(ch[1], ch[1], g);
      mpz_xor(ch[0], ch[0], ch[1]);

      mpz_add(temp1, h_, s1_temp[0]);
      mpz_add(temp1, temp1, ch[0]);
      mpz_add(temp1, temp1, k[i]);
      mpz_add(temp1, temp1, msa[i]);
      mpz_mod_ui(temp1, temp1, 0x100000000);

      r_rotate(s0_temp[0], a, 2);
      r_rotate(s0_temp[0], a, 13);
      r_rotate(s0_temp[0], a, 22);
      mpz_xor(s0_temp[0], s0_temp[0], s0_temp[1]);
      mpz_xor(s0_temp[0], s0_temp[0], s0_temp[2]);

      mpz_and(maj[0], a, b);
      mpz_and(maj[1], a, c);
      mpz_and(maj[2], b, c);
      mpz_xor(maj[0], maj[0], maj[1]);
      mpz_xor(maj[0], maj[0], maj[2]);

      mpz_add(temp2, s0_temp[0], maj[0]);
      mpz_mod_ui(temp2, temp2, 0x100000000);

      mpz_set(h_, g);
      mpz_set(g, f);
      mpz_set(f, e);
      mpz_add(e, d, temp1);
      mpz_set(d, c);
      mpz_set(c, b);
      mpz_set(b, a);
      mpz_add(a, temp1, temp2);
      mpz_mod_ui(a, a, 0x100000000);
    }

    mpz_add(h[0], h[0], a);
    mpz_add(h[1], h[1], b);
    mpz_add(h[2], h[2], c);
    mpz_add(h[3], h[3], d);
    mpz_add(h[4], h[4], e);
    mpz_add(h[5], h[5], f);
    mpz_add(h[6], h[6], g);
    mpz_add(h[7], h[7], h_);

    for (int i = 0; i < 8; i++) {
      mpz_mod_ui(h[i], h[i], 0x100000000);
    }
  }

  // create digest
  for (int i = 0; i < 8; i++) {
    gmp_printf("%Zx", h[i]);
  }

  // clear in order of initialization

  for (int i = 0; i < 8; i++) {
    mpz_clear(h[i]);
  }

  for (int i = 0; i < 64; i++) {
    mpz_clear(k[i]);
  }

  for (int i = 0; i < 64; i++) {
    mpz_clear(msa[i]);
  }

  for (int i = 0; i < 3; i++) {
    mpz_clear(s0_temp[i]);
    mpz_clear(s1_temp[i]);
  }

  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(c);
  mpz_clear(d);
  mpz_clear(e);
  mpz_clear(f);
  mpz_clear(g);
  mpz_clear(h_);
  for (int i = 0; i < 2; i++) {
    mpz_clear(ch[i]);
  }
  mpz_clear(temp1);
  mpz_clear(temp2);
  for (int i = 0; i < 3; i++) {
    mpz_clear(maj[i]);
  }
}

int main() {
  mpz_t a;
  mpz_init_set_str(a, "", 2);
  mpz_t res;

  sha256(res, a);

  return 0;
}