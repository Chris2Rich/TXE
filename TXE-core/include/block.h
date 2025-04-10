#ifndef _BLOCK_H

#define _BLOCK_H
#include <stdint.h>
#include "/workspaces/ecc/TXE-core/include/tx.h"
#include "/workspaces/ecc/TXE-core/include/sha512.h"
#include "/workspaces/ecc/TXE-core/include/db.h"
#include "/workspaces/ecc/TXE-core/include/util.h"
#include <rocksdb/db.h>
#include <math.h>
#include <cstring>
#include <string>
#include <vector>
#include <gmp.h>
#include <time.h>

struct header
{
    unsigned int version;                   // if version changes, this allows for backwards compatability
    unsigned char id[64];                   // hash of header's data (excluding id field) + ancestors' headers - allows for unique ids with ancestors
    unsigned char merkel_root[64];
    unsigned char difficulty_target[64] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // proposed difficulty, verified by consensus
    std::vector<unsigned char *> ancestors; // array of the ids of the ancestors a block has.
    uint64_t timestamp;  // in seconds because the speed of light is 3e8ms-1
    uint64_t nonce;      // for nonce space, this can be relatively small as difficulty will be low

    void create_block_id(unsigned char *id)
    {
        std::unique_ptr<rocksdb::DB> db = open_db(std::string("headers"));
        std::vector<std::string> ancestor_ids = fn_map(uchar_to_string, &ancestors);
        std::vector<std::string> ancestor_data = db_multiget(db.get(), ancestor_ids);
        
        nonce = 0;
        mpz_t h, d;
        mpz_init2(h, 512);
        mpz_init_set_str(d, uchar_to_string(difficulty_target).c_str(), 16);

        while (true)
        {

            std::vector<unsigned char> concat;
            concat.push_back((unsigned char)((version >> 24) & 0xFF));
            concat.push_back((unsigned char)((version >> 16) & 0xFF));
            concat.push_back((unsigned char)((version >> 8) & 0xFF));
            concat.push_back((unsigned char)((version >> 0) & 0xFF));

            for (auto i : ancestors)
            {
                for (int j = 0; j < 64; j++)
                {
                    concat.push_back(i[j]);
                }
            }

            for (int i = 0; i < 64; i++)
            {
                concat.push_back(merkel_root[i]);
            }

            for(int i = 0; i < 64; i++){
                concat.push_back(difficulty_target[i]);
            }

            for (auto i : ancestor_data)
            {
                for (int j = 0; j < i.size(); j++)
                {
                    concat.push_back((unsigned char)i[j]);
                }
            }

            concat.push_back((unsigned char)((timestamp >> 56) & 0xFF));
            concat.push_back((unsigned char)((timestamp >> 48) & 0xFF));
            concat.push_back((unsigned char)((timestamp >> 40) & 0xFF));
            concat.push_back((unsigned char)((timestamp >> 32) & 0xFF));
            concat.push_back((unsigned char)((timestamp >> 24) & 0xFF));
            concat.push_back((unsigned char)((timestamp >> 16) & 0xFF));
            concat.push_back((unsigned char)((timestamp >> 8) & 0xFF));
            concat.push_back((unsigned char)((timestamp >> 0) & 0xFF));

            concat.push_back((unsigned char)((nonce >> 56) & 0xFF));
            concat.push_back((unsigned char)((nonce >> 48) & 0xFF));
            concat.push_back((unsigned char)((nonce >> 40) & 0xFF));
            concat.push_back((unsigned char)((nonce >> 32) & 0xFF));
            concat.push_back((unsigned char)((nonce >> 24) & 0xFF));
            concat.push_back((unsigned char)((nonce >> 16) & 0xFF));
            concat.push_back((unsigned char)((nonce >> 8) & 0xFF));
            concat.push_back((unsigned char)((nonce >> 0) & 0xFF));
        
            mpz_set_str(h, uchar_to_string(hash512(concat).data()).c_str(), 16);

            if(mpz_cmp(d,h)){
                char* temp;
                mpz_get_str(temp, 16, h);
                *id = *(unsigned char*)temp;
                return;
            }

            nonce++;
            timestamp = time(NULL);

        }
    }
};

struct block
{
    unsigned char id[64];                               // stored in block db and associated with a header
    std::vector<std::vector<unsigned char>> merkletree; // first level  in [0], 2nd level in [1,2] 3rd level in [3,4,5,6] etc
    std::vector<tx> tx_list;

    // returns sha512 of the merkle root of the block(more random)
    void create_merkle_root(unsigned char *res)
    {
        std::vector<std::vector<unsigned char>> nodes;
        std::vector<unsigned char> digest(64);
        unsigned char zero_hash[64] = {0};

        size_t tx_count = tx_list.size();
        if (tx_count == 0)
        {
            memset(res, 0, 64);
            return;
        }

        // Compute next power of 2
        size_t leaf_count = 1;
        while (leaf_count < tx_count)
        {
            leaf_count <<= 1;
        }

        // Create leaf nodes
        for (size_t i = 0; i < leaf_count; i++)
        {
            if (i < tx_count)
            {
                nodes.push_back(hash512(tx_list[i].id, 64));
            }
            else
            {
                nodes.push_back(hash512(zero_hash, 64));
            }
        }

        // Build Merkle tree
        while (nodes.size() > 1)
        {
            std::vector<std::vector<unsigned char>> new_nodes;
            for (size_t i = 0; i < nodes.size(); i += 2)
            {
                std::vector<unsigned char> concat(128, 0);
                memcpy(concat.data(), nodes[i].data(), 64);

                if (i + 1 < nodes.size())
                {
                    memcpy(concat.data() + 64, nodes[i + 1].data(), 64);
                }
                else
                {
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