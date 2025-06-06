#ifndef __block
#define __block

#include <tx.h>

#include <randomx.h>
#include <math.h>
#include <vector>
#include <stdint.h>
#include <string>

namespace TXE
{

    struct header
    {
        uint64_t ver;
        uint64_t timestamp;
        uint64_t nonce;
        crypto::hash target;

        std::vector<crypto::hash> tip_ids;
        crypto::hash merkle_root;
        crypto::hash seed;

        crypto::hash header_id;

        std::string get_header_blob() const
        {
            std::string blob;
            blob.append(reinterpret_cast<const char *>(&ver), sizeof(ver));
            blob.append(reinterpret_cast<const char *>(&timestamp), sizeof(timestamp));
            blob.append(reinterpret_cast<const char *>(&nonce), sizeof(nonce));
            blob.append(reinterpret_cast<const char *>(target.data), sizeof(target.data));

            uint64_t tip_count = tip_ids.size();
            blob.append(reinterpret_cast<const char *>(&tip_count), sizeof(tip_count));
            for (const auto &h : tip_ids)
            {
                blob.append(reinterpret_cast<const char *>(h.data), sizeof(h.data));
            }

            blob.append(reinterpret_cast<const char *>(merkle_root.data), sizeof(merkle_root.data));
            blob.append(reinterpret_cast<const char *>(seed.data), sizeof(seed.data));

            return blob;
        }

        void calculate_header_id(crypto::hash& found_valid_hash_output, const crypto::hash& difficulty_target)
        {
            randomx_flags flags = randomx_get_flags();
            randomx_cache *rx_cache = randomx_alloc_cache(flags);
            if (!rx_cache) {
                throw std::runtime_error("Failed to allocate RandomX cache");
            }

            const char randomx_key_for_cache[] = "TXE_RandomX_Seed";
            randomx_init_cache(rx_cache, randomx_key_for_cache, sizeof(randomx_key_for_cache) - 1);

            randomx_vm *rx_vm = randomx_create_vm(flags, rx_cache, nullptr);
            if (!rx_vm) {
                randomx_release_cache(rx_cache);
                throw std::runtime_error("Failed to create RandomX VM");
            }

            char calculated_pow_hash_bytes[RANDOMX_HASH_SIZE];


            while (true)
            {
                std::string blob_to_hash = get_header_blob(); 

                randomx_calculate_hash(rx_vm, blob_to_hash.data(), blob_to_hash.size(), calculated_pow_hash_bytes);

                if (std::memcmp(calculated_pow_hash_bytes, difficulty_target.data, RANDOMX_HASH_SIZE) <= 0)
                {
                    
                    std::memcpy(found_valid_hash_output.data, calculated_pow_hash_bytes, sizeof(found_valid_hash_output.data));
                    
                    std::memcpy(this->header_id.data, calculated_pow_hash_bytes, sizeof(this->header_id.data));
                    
                    break;
                }

                this->nonce++;
                
                if (this->nonce == 0) {
                }
            }

            randomx_destroy_vm(rx_vm);
            randomx_release_cache(rx_cache);
        }

        std::string serialize()
        {
            std::string blob = (*this).get_header_blob();
            blob.append(reinterpret_cast<const char *>(header_id.data), sizeof(header_id.data));
            return blob;
        }

        static header deserialize(const std::string &blob)
        {
            header h;
            size_t offset = 0;
            auto require = [&](size_t sz)
            {
                if (offset + sz > blob.size())
                    throw std::runtime_error("Blob too small for header deserialization");
            };

            require(sizeof(h.ver));
            std::memcpy(&h.ver, blob.data() + offset, sizeof(h.ver));
            offset += sizeof(h.ver);

            require(sizeof(h.timestamp));
            std::memcpy(&h.timestamp, blob.data() + offset, sizeof(h.timestamp));
            offset += sizeof(h.timestamp);

            require(sizeof(h.nonce));
            std::memcpy(&h.nonce, blob.data() + offset, sizeof(h.nonce));
            offset += sizeof(h.nonce);

            require(sizeof(h.target.data));
            std::memcpy(h.target.data, blob.data() + offset, sizeof(h.target.data));
            offset += sizeof(h.target.data);

            uint64_t tip_count = 0;
            require(sizeof(tip_count));
            std::memcpy(&tip_count, blob.data() + offset, sizeof(tip_count));
            offset += sizeof(tip_count);

            h.tip_ids.clear();
            for (uint64_t i = 0; i < tip_count; ++i)
            {
                std::array<unsigned char, 32> data;
                require(data.size());
                std::memcpy(data.data(), blob.data() + offset, data.size());
                offset += data.size();
                crypto::hash ph;
                std::copy(std::begin(data), std::end(data), ph.data);
                h.tip_ids.push_back(ph);
            }

            require(sizeof(h.merkle_root.data));
            std::memcpy(h.merkle_root.data, blob.data() + offset, sizeof(h.merkle_root.data));
            offset += sizeof(h.merkle_root.data);

            require(sizeof(h.seed.data));
            std::memcpy(h.seed.data, blob.data() + offset, sizeof(h.seed.data));
            offset += sizeof(h.seed.data);

            require(sizeof(h.header_id.data));
            std::memcpy(h.header_id.data, blob.data() + offset, sizeof(h.header_id.data));
            offset += sizeof(h.header_id.data);

            return h;
        }
    };

    struct block
    {
        header hdr;
        tx miner_tx;
        std::vector<tx> txlist;

        crypto::hash create_merkle_root()
        {
            std::vector<crypto::hash> tx_hashes;

            std::string miner_blob = miner_tx.serialize_tx();
            crypto::hash miner_hash;
            crypto::cn_fast_hash(miner_blob.data(), miner_blob.size(), miner_hash);
            tx_hashes.push_back(miner_hash);

            for (const auto &transaction : txlist)
            {
                std::string tx_blob = transaction.serialize_tx();
                crypto::hash tx_hash;
                crypto::cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash);
                tx_hashes.push_back(tx_hash);
            }

            if (tx_hashes.size() == 1)
            {
                return tx_hashes[0];
            }

            std::vector<crypto::hash> current_level = tx_hashes;

            while (current_level.size() > 1)
            {
                std::vector<crypto::hash> next_level;

                for (size_t i = 0; i < current_level.size(); i += 2)
                {
                    crypto::hash combined_hash;

                    std::string combined;
                    combined.append(reinterpret_cast<const char *>(current_level[i].data), sizeof(current_level[i].data));

                    if (i + 1 < current_level.size())
                    {
                        combined.append(reinterpret_cast<const char *>(current_level[i + 1].data), sizeof(current_level[i + 1].data));
                    }
                    else
                    {
                        combined.append(reinterpret_cast<const char *>(current_level[i].data), sizeof(current_level[i].data));
                    }

                    crypto::cn_fast_hash(combined.data(), combined.size(), combined_hash);

                    next_level.push_back(combined_hash);
                }

                current_level = std::move(next_level);
            }

            return current_level[0];
        }

        bool verify_transactions(SimpleLMDB &db)
        {
            if (miner_tx.vout.size() != 1)
            {
                return false;
            }

            if (txlist.size() > 4096 || txlist.size() < 1)
            {
                return false;
            }

            bool msucc = miner_tx.ver(db, true, true, false);
            bool tlsucc = true;
            for (auto t : txlist)
            {
                if (!t.ver(db, true, true, true))
                {
                    tlsucc = false;
                }
            }
            if (!((msucc == tlsucc) && (msucc == true)))
            {
                return false;
            }

            std::set<crypto::key_image> block_key_images;
            block_key_images.insert(miner_tx.vin[0].image);

            if (miner_tx.fee != 0)
            {
                return false;
            }

            uint64_t total_fees = 0;
            for (auto t : txlist)
            {
                total_fees += t.fee;
                for (auto in : t.vin)
                {
                    if (block_key_images.count(in.image))
                    {
                        return false;
                    }
                    block_key_images.insert(in.image);
                }
            }

            uint64_t b = db.count_fast("blocks") + 1;

            int k = 100000;
            int r0 = 10000000;
            int step = 25000;

            uint64_t expected_block_reward = round(r0 / sqrt(1 + ((b - (b % step)) / k)));
            uint64_t expected_coinbase = expected_block_reward + total_fees;

            const rct::ecdhTuple &cb_ecdh = miner_tx.signature.ecdhInfo[0];
            const rct::ctkey &cb_outPk_ctkey = miner_tx.signature.outPk[0];

            rct::key calculated_commitment_from_ecdh;
            rct::addKeys2(calculated_commitment_from_ecdh, cb_ecdh.mask, cb_ecdh.amount, rct::H);

            if (!(calculated_commitment_from_ecdh == cb_outPk_ctkey.mask))
            {
                return false;
            }

            if (rct::h2d(cb_ecdh.amount) != expected_coinbase)
            {
                return false;
            }

            return true;
        }

        std::string serialize_block()
        {
            std::string blob = hdr.serialize();

            std::string miner_blob = miner_tx.serialize_tx();
            uint64_t miner_len = miner_blob.size();
            blob.append(reinterpret_cast<const char *>(&miner_len), sizeof(miner_len));
            blob.append(miner_blob);

            uint64_t tx_count = txlist.size();
            blob.append(reinterpret_cast<const char *>(&tx_count), sizeof(tx_count));
            for (auto const &x : txlist)
            {
                std::string tx_blob = x.serialize_tx();
                uint64_t len = tx_blob.size();
                blob.append(reinterpret_cast<const char *>(&len), sizeof(len));
                blob.append(tx_blob);
            }

            return blob;
        }

        static block deserialize_block(const std::string &blob)
        {
            block b;
            size_t offset = 0;

            b.hdr = header::deserialize(blob);
            size_t header_size = b.hdr.get_header_blob().size() + sizeof(b.hdr.header_id.data);
            offset = header_size;

            std::cout << "deserialized header" << std::endl;

            auto require = [&](size_t sz)
            {
                if (offset + sz > blob.size())
                    throw std::runtime_error("Blob too small for block deserialization");
            };

            require(sizeof(uint64_t));
            uint64_t miner_len;
            std::memcpy(&miner_len, blob.data() + offset, sizeof(miner_len));
            offset += sizeof(miner_len);
            require(miner_len);
            b.miner_tx = tx::deserialize_tx(blob.substr(offset, miner_len));
            offset += miner_len;

            std::cout << "deserialized miner tx" << std::endl;

            require(sizeof(uint64_t));
            uint64_t tx_count;
            std::memcpy(&tx_count, blob.data() + offset, sizeof(tx_count));
            offset += sizeof(tx_count);
            b.txlist.resize(tx_count);
            for (uint64_t i = 0; i < tx_count; ++i)
            {
                require(sizeof(uint64_t));
                uint64_t len;
                std::memcpy(&len, blob.data() + offset, sizeof(len));
                offset += sizeof(len);
                require(len);
                b.txlist[i] = tx::deserialize_tx(blob.substr(offset, len));
                offset += len;
            }

            std::cout << "deserialized " << tx_count << " tx" << std::endl;

            return b;
        }

        static void add_block_to_db(block b, SimpleLMDB *db)
        {
            db->put("blocks", std::string(reinterpret_cast<const char *>(b.hdr.header_id.data), sizeof(b.hdr.header_id.data)), b.serialize_block());
            db->put("tips", "0", std::string(reinterpret_cast<const char *>(b.hdr.header_id.data), sizeof(b.hdr.header_id.data)));
            crypto::hash tx_hash;
            crypto::cn_fast_hash(b.miner_tx.serialize_tx().data(), sizeof(b.miner_tx.serialize_tx().data()), tx_hash);
            db->put("key_images", std::string(reinterpret_cast<const char *>(b.miner_tx.vin[0].image.data), sizeof(b.miner_tx.vin[0].image.data)), std::string(reinterpret_cast<const char *>(tx_hash.data), sizeof(tx_hash.data)));
            for (auto t : b.txlist)
            {
                std::string txstr = t.serialize_tx();
                crypto::cn_fast_hash(&txstr, sizeof(txstr.data()), tx_hash);
                db->put("transactions", std::string(reinterpret_cast<const char *>(tx_hash.data), sizeof(tx_hash.data)), txstr);
                for (auto in : t.vin)
                {
                    db->put("key_images", std::string(reinterpret_cast<const char *>(in.image.data), sizeof(in.image.data)), std::string(reinterpret_cast<const char *>(tx_hash.data), sizeof(tx_hash.data)));
                }
                for (auto out : t.vout)
                {
                    db->put("outputs", std::string(reinterpret_cast<const char *>(out.ephemeral_pub_key.data), sizeof(out.ephemeral_pub_key.data)), out.serialize());
                    db->put("output_indexes", std::to_string(db->count_fast("output_indexes") + 1), std::string(reinterpret_cast<const char *>(out.commitment.bytes), sizeof(out.commitment.bytes)) + std::string(reinterpret_cast<const char *>(out.ephemeral_pub_key.data), sizeof(out.ephemeral_pub_key.data)));
                }
            }
        }
    };
}

#endif
