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
};

struct block {
    header hdr;
    crypto::hash block_id;
    tx miner_tx; // Coinbase / miner reward transaction
    std::vector<tx> txlist; // Normal transactions
};
}

#endif