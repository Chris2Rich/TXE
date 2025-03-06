#include <stdint.h>
#include "../tx/tx.cpp"
#include "../crypto/sha512.cpp"
#include <math.h>
#include <cstring>
#include <vector>

struct header {
    unsigned int version; // if version changes, this allows for backwards compatability
    unsigned char id[64]; //hash of concatenation of ancestors' data - allows for unique ids with ancestors
    std::vector<unsigned char> ancestors; //concatenation of the ids of the ancestors a block has. 
    unsigned char nonce[64]; // for nonce space, this should be equal to the size of the domain of the hash function
    unsigned char merkel_root[64];
    uint32_t difficulty; //proposed difficulty, verified by consensus
};

struct block {
    unsigned char id[64]; //stored in db and ID is used for rapid indexing into b-tree
    std::vector<tx> tx_list;

    //returns sha512 of the merkle root of the block(more random)
    void create_merkle_root(unsigned char* res) {
        CryptoPP::SHA512 hash;
        std::vector<std::vector<unsigned char>> nodes;
        std::vector<unsigned char> digest(64);
        unsigned char zero_hash[64] = {0};

        size_t tx_count = tx_list.size();
        if (tx_count == 0) {
            memset(res, 0, 64);
            return;
        }

        // Compute next power of 2
        size_t leaf_count = 1;
        while (leaf_count < tx_count) {
            leaf_count <<= 1;
        }

        // Create leaf nodes
        for (size_t i = 0; i < leaf_count; i++) {
            if (i < tx_count) {
                hash.Update(tx_list[i].id, 64);
            } else {
                hash.Update(zero_hash, 64);
            }
            hash.Final(digest.data());
            nodes.push_back(digest);
        }

        // Build Merkle tree
        while (nodes.size() > 1) {
            std::vector<std::vector<unsigned char>> new_nodes;
            for (size_t i = 0; i < nodes.size(); i += 2) {
                std::vector<unsigned char> concat(128, 0);
                memcpy(concat.data(), nodes[i].data(), 64);

                if (i + 1 < nodes.size()) {
                    memcpy(concat.data() + 64, nodes[i + 1].data(), 64);
                } else {
                    // Hash the last node with itself if odd number
                    hash.Update(nodes[i].data(), 64);
                    hash.Update(nodes[i].data(), 64);
                    hash.Final(digest.data());
                    new_nodes.push_back(digest);
                    break;
                }

                hash.Update(concat.data(), 128);
                hash.Final(digest.data());
                new_nodes.push_back(digest);
            }

            nodes = new_nodes;
        }

        // Copy the Merkle root
        memcpy(res, nodes[0].data(), 64);
    }
};

int main(){
    block bloc;
    tx a(61);
    tx b(62);
    tx c(63);
    tx d(64);
    unsigned char res[64];
    bloc.tx_list = {a,b,c,d};
    bloc.create_merkle_root(res);
    return 0;
}