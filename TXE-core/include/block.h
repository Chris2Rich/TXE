#ifndef _BLOCK_H

#define _BLOCK_H
#include <stdint.h>
#include "/workspaces/ecc/TXE-core/include/tx.h"
#include "/workspaces/ecc/TXE-core/include/sha512.h"
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
    std::vector<std::vector<unsigned char>> merkletree; //first level  in [0], 2nd level in [1,2] 3rd level in [3,4,5,6] etc 
    std::vector<tx> tx_list;
    
    //returns sha512 of the merkle root of the block(more random)
    void create_merkle_root(unsigned char* res) {
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
                nodes.push_back(hash512(tx_list[i].id, 64));
            } else {
                nodes.push_back(hash512(zero_hash, 64));
            }
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
                    new_nodes.push_back(hash512(hash512(nodes[i])));
                    break;
                }
                
                new_nodes.push_back(hash512(concat));
            }
            
            nodes = new_nodes;
        }
        
        // Copy the Merkle root
        memcpy(res, nodes[0].data(), 64);
    }
};
#endif // _BLOCK_H