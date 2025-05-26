#include <crypto/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <iostream>

namespace TXE {
struct WalletKeys {
  crypto::public_key  view_pub;
  crypto::secret_key  view_sec;
  crypto::public_key  spend_pub;
  crypto::secret_key  spend_sec;

  static WalletKeys generate() {
    WalletKeys w;
    crypto::generate_keys(w.spend_pub, w.spend_sec);
    crypto::generate_keys(w.view_pub,  w.view_sec);
    return w;
  }

private:
  // Derive a 32-byte key from password+salt
  static void derive_key(const std::string& password, const crypto::hash& salt, unsigned char out_key[32]) {
    crypto::hash h;
    std::string combined = password + std::string((char*)&salt, sizeof(salt));
    crypto::cn_fast_hash(combined.data(), combined.size(), h);
    std::memcpy(out_key, h.data, 32);
  }

public:
  void save(const std::string &filename, const std::string& password) {
    // 1) Open file
    std::ofstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file for writing");

    // 2) Generate random salt
    crypto::hash salt;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data), sizeof(salt)) != 1)
    throw std::runtime_error("RAND_bytes failed");

    // 3) Derive AES‑256 key
    unsigned char key[32];
    derive_key(password, salt, key);

    // 4) Generate random IV (16 bytes)
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1)
      throw std::runtime_error("RAND_bytes failed");

    // 5) Serialize plaintext blob (keys) into buffer
    unsigned char plaintext[sizeof(view_pub)+sizeof(view_sec) +
                            sizeof(spend_pub)+sizeof(spend_sec)];
    unsigned char* p = plaintext;
    std::memcpy(p, &view_pub,  sizeof(view_pub));   p += sizeof(view_pub);
    std::memcpy(p, &view_sec,  sizeof(view_sec));   p += sizeof(view_sec);
    std::memcpy(p, &spend_pub, sizeof(spend_pub));  p += sizeof(spend_pub);
    std::memcpy(p, &spend_sec, sizeof(spend_sec));  p += sizeof(spend_sec);
    int plaintext_len = p - plaintext;

    // 6) Encrypt with AES‑256‑CBC + PKCS#7 (via OpenSSL EVP)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
      throw std::runtime_error("EVP_EncryptInit_ex failed");

    std::vector<unsigned char> ciphertext(plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen1=0, outlen2=0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen1, plaintext, plaintext_len) != 1)
      throw std::runtime_error("EVP_EncryptUpdate failed");
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data()+outlen1, &outlen2) != 1)
      throw std::runtime_error("EVP_EncryptFinal_ex failed");
    EVP_CIPHER_CTX_free(ctx);
    int cipher_len = outlen1 + outlen2;

    // 7) Write salt, iv, cipher_len, then ciphertext
    f.write((char*)&salt,       sizeof(salt));
    f.write((char*)iv,          sizeof(iv));
    uint32_t clen = cipher_len;
    f.write((char*)&clen,       sizeof(clen));
    f.write((char*)ciphertext.data(), cipher_len);
  }

  static WalletKeys load(const std::string &filename, const std::string& password) {
    std::ifstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file for reading");

    // 1) Read salt, iv, cipher_len
    crypto::hash salt;
    f.read((char*)&salt, sizeof(salt));
    unsigned char iv[16];
    f.read((char*)iv, sizeof(iv));
    uint32_t cipher_len = 0;
    f.read((char*)&cipher_len, sizeof(cipher_len));

    // 2) Read ciphertext
    std::vector<unsigned char> ciphertext(cipher_len);
    f.read((char*)ciphertext.data(), cipher_len);

    // 3) Derive AES key
    unsigned char key[32];
    derive_key(password, salt, key);

    // 4) Decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
      throw std::runtime_error("EVP_DecryptInit_ex failed");

    std::vector<unsigned char> plaintext(cipher_len);
    int outlen1=0, outlen2=0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1,
                          ciphertext.data(), cipher_len) != 1)
      throw std::runtime_error("EVP_DecryptUpdate failed (wrong password?)");
    if (EVP_DecryptFinal_ex(ctx, plaintext.data()+outlen1, &outlen2) != 1)
      throw std::runtime_error("EVP_DecryptFinal_ex failed (wrong password?)");
    EVP_CIPHER_CTX_free(ctx);
    int p_len = outlen1 + outlen2;

    // 5) Unpack keys from plaintext
    if ((size_t)p_len != sizeof(crypto::public_key)*2 + sizeof(crypto::secret_key)*2)
      throw std::runtime_error("Decrypted length mismatch");

    WalletKeys w;
    unsigned char* p = plaintext.data();
    std::memcpy(&w.view_pub,  p, sizeof(w.view_pub));   p += sizeof(w.view_pub);
    std::memcpy(&w.view_sec,  p, sizeof(w.view_sec));   p += sizeof(w.view_sec);
    std::memcpy(&w.spend_pub, p, sizeof(w.spend_pub));  p += sizeof(w.spend_pub);
    std::memcpy(&w.spend_sec, p, sizeof(w.spend_sec));  p += sizeof(w.spend_sec);

    return w;
  }
};
}
