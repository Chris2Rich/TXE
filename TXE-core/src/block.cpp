#ifndef __block
#define __block

#include "tx.cpp"
#include <vector>
#include <stdint.h>
#include <string>

namespace TXE {

struct header {
    uint64_t ver; // Version (usually 1 or 2)
    uint64_t timestamp; // Unix timestamp
    uint64_t nonce; // Nonce for RandomX

    std::vector<crypto::hash> tip_ids; // Direct parents (tips)
    crypto::hash merkle_root; // Proof transactions haven't been changed

    crypto::hash header_id;

    // Serialization of header for hashing (RandomX input)
    std::string get_header_blob() const {
        std::string blob;
        blob.append(reinterpret_cast<const char*>(&ver), sizeof(ver));
        blob.append(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
        blob.append(reinterpret_cast<const char*>(&nonce), sizeof(nonce));

        uint64_t tip_count = tip_ids.size();
        blob.append(reinterpret_cast<const char*>(&tip_count), sizeof(tip_count));
        // Serialize tip hashes
        for (const auto& h : tip_ids){
            blob.append(reinterpret_cast<const char*>(h.data), sizeof(h.data));
        }

        blob.append(reinterpret_cast<const char*>(merkle_root.data), sizeof(merkle_root.data));

        return blob;
    }

    std::string serialize() {
        std::string blob = (*this).get_header_blob();
        blob.append(reinterpret_cast<const char*>(header_id.data), sizeof(header_id.data));
        return blob;
    }

    // Deserialize a header from a binary blob
    static header deserialize(const std::string& blob) {
        header h;
        size_t offset = 0;
        auto require = [&](size_t sz) {
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
        for (uint64_t i = 0; i < tip_count; ++i) {
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

        // Read header_id
        require(sizeof(h.header_id.data));
        std::memcpy(h.header_id.data, blob.data() + offset, sizeof(h.header_id.data));
        offset += sizeof(h.header_id.data);

        return h;
    }
};

struct block {
    header hdr;
    crypto::hash block_id;
    tx miner_tx; // Coinbase / miner reward transaction
    std::vector<tx> txlist; // Normal transactions

    std::string serialize_block(const block b){
        std::string blob = hdr.serialize();
        blob.append(reinterpret_cast<const char*>(&block_id.data), sizeof(block_id.data));
    
        uint64_t tx_count = txlist.size();
        blob.append(reinterpret_cast<const char*>(&tx_count), sizeof(tx_count));
    }

    static block deserialize_block(const std::string b){
        
    }
};
}

#endif