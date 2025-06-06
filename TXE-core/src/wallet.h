#ifndef __wallet
#define __wallet

#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include "db.h"
#include "tx.h"
#include "block.h"
#include "device/device.hpp"

namespace TXE
{
  struct SpendableOutputInfo
  {
    uint64_t amount;
    rct::key sk_x;
    rct::key mask_a;
    rct::ctkey pk_on_chain;
    size_t global_index;
  };

  struct WalletKeys
  {
    crypto::public_key view_pub;
    crypto::secret_key view_sec;
    crypto::public_key spend_pub;
    crypto::secret_key spend_sec;

    static WalletKeys generate()
    {
      WalletKeys w;
      crypto::generate_keys(w.spend_pub, w.spend_sec);
      crypto::generate_keys(w.view_pub, w.view_sec);
      return w;
    }

  private:
    static void derive_key(const std::string &password, const crypto::hash &salt, unsigned char out_key[32])
    {
      const int iterations = 10000;
      crypto::hash current = salt;

      for (int i = 0; i < iterations; ++i)
      {
        std::string combined = password + std::string((char *)&current, sizeof(current));
        crypto::cn_fast_hash(combined.data(), combined.size(), current);
      }

      std::memcpy(out_key, current.data, 32);
    }

  public:
    void save(const std::string &filename, const std::string &password)
    {
      std::ofstream f(filename, std::ios::binary);
      if (!f)
        throw std::runtime_error("Cannot open file for writing");

      crypto::hash salt;
      if (RAND_bytes(reinterpret_cast<unsigned char *>(salt.data), sizeof(salt)) != 1)
        throw std::runtime_error("RAND_bytes failed");

      unsigned char key[32];
      derive_key(password, salt, key);

      unsigned char iv[16];
      if (RAND_bytes(iv, sizeof(iv)) != 1)
        throw std::runtime_error("RAND_bytes failed");

      unsigned char plaintext[sizeof(view_pub.data) + sizeof(view_sec.data) +
                              sizeof(spend_pub.data) + sizeof(spend_sec.data)];
      unsigned char *p = plaintext;
      std::memcpy(p, view_pub.data, sizeof(view_pub.data));
      p += sizeof(view_pub.data);
      std::memcpy(p, view_sec.data, sizeof(view_sec.data));
      p += sizeof(view_sec.data);
      std::memcpy(p, spend_pub.data, sizeof(spend_pub.data));
      p += sizeof(spend_pub.data);
      std::memcpy(p, spend_sec.data, sizeof(spend_sec.data));
      p += sizeof(spend_sec.data);
      int plaintext_len = p - plaintext;

      EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
      if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
      if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

      std::vector<unsigned char> ciphertext(plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
      int outlen1 = 0, outlen2 = 0;
      if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen1, plaintext, plaintext_len) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");
      if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen1, &outlen2) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
      EVP_CIPHER_CTX_free(ctx);
      int cipher_len = outlen1 + outlen2;

      f.write((char *)&salt, sizeof(salt));
      f.write((char *)iv, sizeof(iv));
      uint32_t clen = cipher_len;
      f.write((char *)&clen, sizeof(clen));
      f.write((char *)ciphertext.data(), cipher_len);
    }

    static WalletKeys load(const std::string &filename, const std::string &password)
    {
      std::ifstream f(filename, std::ios::binary);
      if (!f)
        throw std::runtime_error("Cannot open file for reading");

      crypto::hash salt;
      f.read((char *)&salt, sizeof(salt));
      unsigned char iv[16];
      f.read((char *)iv, sizeof(iv));
      uint32_t cipher_len = 0;
      f.read((char *)&cipher_len, sizeof(cipher_len));

      std::vector<unsigned char> ciphertext(cipher_len);
      f.read((char *)ciphertext.data(), cipher_len);

      unsigned char key[32];
      derive_key(password, salt, key);

      EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
      if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
      if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

      std::vector<unsigned char> plaintext(cipher_len);
      int outlen1 = 0, outlen2 = 0;
      if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1,
                            ciphertext.data(), cipher_len) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed (wrong password?)");
      if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen1, &outlen2) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed (wrong password?)");
      EVP_CIPHER_CTX_free(ctx);
      int p_len = outlen1 + outlen2;

      if ((size_t)p_len != sizeof(crypto::public_key) * 2 + sizeof(crypto::secret_key) * 2)
        throw std::runtime_error("Decrypted length mismatch");

      WalletKeys w;
      unsigned char *p = plaintext.data();
      std::memcpy(w.view_pub.data, p, sizeof(w.view_pub.data));
      p += sizeof(w.view_pub.data);
      std::memcpy(w.view_sec.data, p, sizeof(w.view_sec.data));
      p += sizeof(w.view_sec.data);
      std::memcpy(w.spend_pub.data, p, sizeof(w.spend_pub.data));
      p += sizeof(w.spend_pub.data);
      std::memcpy(w.spend_sec.data, p, sizeof(w.spend_sec.data));
      p += sizeof(w.spend_sec.data);

      return w;
    }

    std::vector<SpendableOutputInfo> get_owned(
    MDB_txn *active_read_txn,
    MDB_dbi dbi_blocks_handle,
    MDB_dbi dbi_key_images_handle
)
{
    std::vector<SpendableOutputInfo> owned_spendable_outputs;
    hw::device &hwdev = hw::get_device("default");


    std::vector<std::pair<uint64_t, TXE::block>> temp_block_storage;
    MDB_cursor *cursor_blocks;
    if (mdb_cursor_open(active_read_txn, dbi_blocks_handle, &cursor_blocks))
    {
        throw std::runtime_error("get_owned (block_scan): Failed to open cursor for blocks table using provided handle.");
    }
    MDB_val mdb_block_key, mdb_block_value;
    while (mdb_cursor_get(cursor_blocks, &mdb_block_key, &mdb_block_value, MDB_NEXT) == 0)
    {
        std::string block_blob(static_cast<char *>(mdb_block_value.mv_data), mdb_block_value.mv_size);
        try
        {
            TXE::block current_block = TXE::block::deserialize_block(block_blob);
            temp_block_storage.push_back({current_block.hdr.timestamp, current_block});
        }
        catch (const std::exception &e)
        {
        }
    }
    mdb_cursor_close(cursor_blocks);

    std::sort(temp_block_storage.begin(), temp_block_storage.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });

    size_t running_global_output_index = 0;

    for (const auto &pair_ts_block : temp_block_storage)
    {
        const TXE::block &current_block = pair_ts_block.second;
        std::vector<const TXE::tx *> txs_in_block;
        txs_in_block.push_back(&current_block.miner_tx);
        for (const auto &tx_from_list : current_block.txlist)
        {
            txs_in_block.push_back(&tx_from_list);
        }

        for (const TXE::tx *p_current_tx : txs_in_block)
        {
            const TXE::tx &current_tx = *p_current_tx;
            if (current_tx.extra.size() < sizeof(crypto::public_key))
            {
                running_global_output_index += current_tx.signature.outPk.size();
                continue;
            }
            crypto::public_key tx_R_key;
            std::memcpy(tx_R_key.data, current_tx.extra.data(), sizeof(crypto::public_key));

            for (size_t out_idx_in_tx = 0; out_idx_in_tx < current_tx.signature.outPk.size(); ++out_idx_in_tx)
            {
                const rct::ctkey &output_ctkey = current_tx.signature.outPk[out_idx_in_tx];
                crypto::public_key P_on_chain_crypto;
                std::memcpy(P_on_chain_crypto.data, output_ctkey.dest.bytes, sizeof(crypto::public_key));

                crypto::key_derivation derivation;
                if (!crypto::generate_key_derivation(tx_R_key, this->view_sec, derivation))
                {
                    running_global_output_index++;
                    continue;
                }
                crypto::public_key P_candidate;
                if (!crypto::derive_public_key(derivation, out_idx_in_tx, this->spend_pub, P_candidate))
                {
                    running_global_output_index++;
                    continue;
                }

                if (P_candidate == P_on_chain_crypto)
                {
                    crypto::secret_key x_one_time_sk_crypto;
                    crypto::derive_secret_key(derivation, out_idx_in_tx, this->spend_sec, x_one_time_sk_crypto);
                    crypto::key_image ki;
                    crypto::generate_key_image(P_on_chain_crypto, x_one_time_sk_crypto, ki);

                    MDB_val ki_mdb_key{sizeof(crypto::key_image), (void *)ki.data};
                    MDB_val ki_mdb_value;
                    bool is_spent = (mdb_get(active_read_txn, dbi_key_images_handle, &ki_mdb_key, &ki_mdb_value) == 0);

                    if (!is_spent)
                    {
                        uint64_t decoded_amount = 0; 
                        rct::key decoded_mask_a;   

                        crypto::ec_scalar s_j_scalar;
                        crypto::derivation_to_scalar(derivation, out_idx_in_tx, s_j_scalar);
                        rct::key s_j_rct_key = rct::sk2rct(reinterpret_cast<const crypto::secret_key &>(s_j_scalar));

                        if (out_idx_in_tx >= current_tx.signature.ecdhInfo.size())
                        {
                            running_global_output_index++; 
                            continue;
                        }
                        try
                        {
                            decoded_amount = rct::decodeRctSimple(
                                current_tx.signature,
                                s_j_rct_key,
                                static_cast<unsigned int>(out_idx_in_tx), 
                                decoded_mask_a,                         
                                hwdev);
                            SpendableOutputInfo info;
                            info.amount = decoded_amount;
                            info.sk_x = rct::sk2rct(x_one_time_sk_crypto);
                            info.mask_a = decoded_mask_a;
                            info.pk_on_chain = output_ctkey;
                            info.global_index = running_global_output_index;
                            owned_spendable_outputs.push_back(info);
                        }
                        catch (const std::exception &e) { /* ... logging ... */ }
                    }
                }
                running_global_output_index++; 
            } 
        } 
    } 
    return owned_spendable_outputs;
}
  };
}

#endif
