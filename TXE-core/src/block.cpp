#ifndef __block
#define __block

#include "tx.cpp"
#include <vector>
#include <stdint.h>
#include <string>
#include <randomx.h>

namespace TXE
{

    struct header
    {
        uint64_t ver;       // Version (usually 1 or 2)
        uint64_t timestamp; // Unix timestamp
        uint64_t nonce;     // Nonce for RandomX

        std::vector<crypto::hash> tip_ids; // Direct parents (tips)
        crypto::hash merkle_root;          // Proof transactions haven't been changed
        crypto::hash seed;                 // the randomx seed the block was mined with

        crypto::hash header_id;

        // Serialization of header for hashing (RandomX input)
        std::string get_header_blob() const
        {
            std::string blob;
            blob.append(reinterpret_cast<const char *>(&ver), sizeof(ver));
            blob.append(reinterpret_cast<const char *>(&timestamp), sizeof(timestamp));
            blob.append(reinterpret_cast<const char *>(&nonce), sizeof(nonce));

            uint64_t tip_count = tip_ids.size();
            blob.append(reinterpret_cast<const char *>(&tip_count), sizeof(tip_count));
            // Serialize tip hashes
            for (const auto &h : tip_ids)
            {
                blob.append(reinterpret_cast<const char *>(h.data), sizeof(h.data));
            }

            blob.append(reinterpret_cast<const char *>(merkle_root.data), sizeof(merkle_root.data));
            blob.append(reinterpret_cast<const char *>(seed.data), sizeof(seed.data));

            return blob;
        }

        void calculate_header_id()
        {
            // Get the header blob (without the header_id itself)
            std::string blob = get_header_blob();

            // Initialize RandomX
            randomx_flags flags = randomx_get_flags();
            randomx_cache *cache = randomx_alloc_cache(flags);

            // Use the seed for RandomX
            // seed will be generated from "super" hashes which are 1-500x lower than difficulty.
            const char seed[] = "TXE_RandomX_Seed";
            randomx_init_cache(cache, seed, sizeof(seed) - 1);

            randomx_vm *vm = randomx_create_vm(flags, cache, nullptr);

            // Calculate hash
            char hash_output[RANDOMX_HASH_SIZE];
            randomx_calculate_hash(vm, blob.data(), blob.size(), hash_output);

            // Copy the hash to header_id
            std::memcpy(header_id.data, hash_output, sizeof(header_id.data));

            // Cleanup
            randomx_destroy_vm(vm);
            randomx_release_cache(cache);
        }

        std::string serialize()
        {
            std::string blob = (*this).get_header_blob();
            blob.append(reinterpret_cast<const char *>(header_id.data), sizeof(header_id.data));
            return blob;
        }

        // Deserialize a header from a binary blob
        static header deserialize(const std::string &blob)
        {
            header h;
            size_t offset = 0;
            auto require = [&](size_t sz)
            {
                if (offset + sz > blob.size())
                    throw std::runtime_error("Blob too small for header deserialization");
            };

            // Read ver
            require(sizeof(h.ver));
            std::memcpy(&h.ver, blob.data() + offset, sizeof(h.ver));
            offset += sizeof(h.ver);

            // Read timestamp
            require(sizeof(h.timestamp));
            std::memcpy(&h.timestamp, blob.data() + offset, sizeof(h.timestamp));
            offset += sizeof(h.timestamp);

            // Read nonce
            require(sizeof(h.nonce));
            std::memcpy(&h.nonce, blob.data() + offset, sizeof(h.nonce));
            offset += sizeof(h.nonce);

            // Read tip count
            uint64_t tip_count = 0;
            require(sizeof(tip_count));
            std::memcpy(&tip_count, blob.data() + offset, sizeof(tip_count));
            offset += sizeof(tip_count);

            // Read each tip hash
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

            // Read merkle_root
            require(sizeof(h.merkle_root.data));
            std::memcpy(h.merkle_root.data, blob.data() + offset, sizeof(h.merkle_root.data));
            offset += sizeof(h.merkle_root.data);

            // Read seed
            require(sizeof(h.seed.data));
            std::memcpy(h.seed.data, blob.data() + offset, sizeof(h.seed.data));
            offset += sizeof(h.seed.data);

            // Read header_id
            require(sizeof(h.header_id.data));
            std::memcpy(h.header_id.data, blob.data() + offset, sizeof(h.header_id.data));
            offset += sizeof(h.header_id.data);

            return h;
        }
    };

    struct block
    {
        header hdr;
        crypto::hash block_id;
        tx miner_tx;            // Coinbase / miner reward transaction
        std::vector<tx> txlist; // Normal transactions

        crypto::hash create_merkle_root()
        {
            std::vector<crypto::hash> tx_hashes;

            // Add miner transaction hash
            std::string miner_blob = miner_tx.serialize_tx();
            crypto::hash miner_hash;
            crypto::cn_fast_hash(miner_blob.data(), miner_blob.size(), miner_hash);
            tx_hashes.push_back(miner_hash);

            // Add all regular transaction hashes
            for (const auto &transaction : txlist)
            {
                std::string tx_blob = transaction.serialize_tx();
                crypto::hash tx_hash;
                crypto::cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash);
                tx_hashes.push_back(tx_hash);
            }

            // Handle single transaction case
            if (tx_hashes.size() == 1)
            {
                return tx_hashes[0];
            }

            // Build Merkle tree bottom-up
            std::vector<crypto::hash> current_level = tx_hashes;

            while (current_level.size() > 1)
            {
                std::vector<crypto::hash> next_level;

                // Process pairs of hashes
                for (size_t i = 0; i < current_level.size(); i += 2)
                {
                    crypto::hash combined_hash;

                    std::string combined;
                    combined.append(reinterpret_cast<const char *>(current_level[i].data), sizeof(current_level[i].data));

                    if (i + 1 < current_level.size())
                    {
                        // Hash pair of different hashes
                        combined.append(reinterpret_cast<const char *>(current_level[i + 1].data), sizeof(current_level[i + 1].data));
                    }
                    else
                    {
                        // Odd number of hashes - duplicate the last hash (Bitcoin standard)
                        combined.append(reinterpret_cast<const char *>(current_level[i].data), sizeof(current_level[i].data));
                    }

                    crypto::cn_fast_hash(combined.data(), combined.size(), combined_hash);

                    next_level.push_back(combined_hash);
                }

                current_level = std::move(next_level);
            }

            return current_level[0];
        }

        std::string serialize_block(const block b)
        {
            std::string blob = hdr.serialize();
            blob.append(reinterpret_cast<const char *>(block_id.data), sizeof(block_id.data));

            // miner_tx
            std::string miner_blob = miner_tx.serialize_tx();
            // prefix length for miner tx
            uint64_t miner_len = miner_blob.size();
            blob.append(reinterpret_cast<const char *>(&miner_len), sizeof(miner_len));
            blob.append(miner_blob);

            // txlist
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

            // 1) header
            b.hdr = header::deserialize(blob);
            size_t header_size = b.hdr.get_header_blob().size() + sizeof(b.hdr.header_id.data);
            offset = header_size;

            // 2) block_id
            auto require = [&](size_t sz)
            {
                if (offset + sz > blob.size())
                    throw std::runtime_error("Blob too small for block deserialization");
            };
            require(sizeof(b.block_id.data));
            std::memcpy(b.block_id.data, blob.data() + offset, sizeof(b.block_id.data));
            offset += sizeof(b.block_id.data);

            // 3) miner_tx
            require(sizeof(uint64_t));
            uint64_t miner_len;
            std::memcpy(&miner_len, blob.data() + offset, sizeof(miner_len));
            offset += sizeof(miner_len);
            require(miner_len);
            b.miner_tx = tx::deserialize_tx(blob.substr(offset, miner_len));
            offset += miner_len;

            // 4) txlist
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

            return b;
        }
    };
}

#endif