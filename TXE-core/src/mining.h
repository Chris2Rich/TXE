#ifndef __mining
#define __mining

#include <block.h>
#include <tx.h>
#include <db.h>

#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <array>

namespace TXE
{

    static uint64_t get_block_reward(SimpleLMDB &db)
    {
        uint64_t b = db.count_fast("blocks") + 1;

        int k = 100000;
        int r0 = 10000000;
        int step = 25000;

        return round(r0 / sqrt(1 + ((b - (b % step)) / k)));
    }

    struct uint256_t
    {
        std::array<uint64_t, 4> limbs; // limb[0]=MSB, limb[3]=LSB

        uint256_t(uint64_t val = 0)
        {
            limbs.fill(0);
            limbs[3] = val; // Set LSB, other limbs (MSB) are 0
        }

        // Constructor from big-endian byte array (crypto::hash)
        uint256_t(const crypto::hash &h_be)
        {
            const unsigned char *hash_bytes = reinterpret_cast<const unsigned char *>(h_be.data);
            for (int i = 0; i < 4; ++i)
            { // limbs[0] = MSB from h_be.data[0..7]
                uint64_t current_limb = 0;
                const unsigned char *ptr = hash_bytes + i * 8;
                for (int k = 0; k < 8; ++k)
                {
                    current_limb = (current_limb << 8) | ptr[k];
                }
                limbs[i] = current_limb;
            }
        }

        // Convert to big-endian byte array (crypto::hash)
        crypto::hash to_hash() const
        {
            crypto::hash h_be;
            unsigned char *hash_bytes = reinterpret_cast<unsigned char *>(h_be.data);
            for (int i = 0; i < 4; ++i)
            { // limbs[0] (MSB) to h_be.data[0..7]
                uint64_t val = limbs[i];
                unsigned char *ptr = hash_bytes + i * 8;
                for (int k = 7; k >= 0; --k)
                { // Write bytes in BE order
                    ptr[k] = val & 0xFF;
                    val >>= 8;
                }
            }
            return h_be;
        }

        bool is_zero() const
        {
            for (int i = 0; i < 4; ++i)
                if (limbs[i] != 0)
                    return false;
            return true;
        }

        bool operator<(const uint256_t &other) const
        {
            for (int i = 0; i < 4; ++i)
            { // Compare from MSB
                if (limbs[i] < other.limbs[i])
                    return true;
                if (limbs[i] > other.limbs[i])
                    return false;
            }
            return false; // Equal
        }

        bool operator==(const uint256_t &other) const
        {
            return limbs == other.limbs;
        }

        // Uses GCC/Clang extension for unsigned __int128.
        uint256_t multiply(uint64_t scalar) const
        {
            uint256_t result(0);
            unsigned __int128 carry = 0;
            for (int i = 3; i >= 0; --i)
            { // LSB to MSB for limbs
                unsigned __int128 prod = (unsigned __int128)limbs[i] * scalar + carry;
                result.limbs[i] = (uint64_t)prod;
                carry = prod >> 64;
            }
            // Note: Does not handle overflow if final carry > 0.
            // This should be clamped by MAX_TARGET at a higher level.
            return result;
        }

        // Uses GCC/Clang extension for unsigned __int128.
        uint256_t divide(uint64_t scalar) const
        {
            if (scalar == 0)
                throw std::runtime_error("uint256_t::divide by zero");
            uint256_t result(0);
            unsigned __int128 remainder_carry = 0;
            for (int i = 0; i < 4; ++i)
            { // MSB to LSB for limbs
                unsigned __int128 dividend_part = (remainder_carry << 64) + limbs[i];
                result.limbs[i] = (uint64_t)(dividend_part / scalar);
                remainder_carry = dividend_part % scalar;
            }
            return result;
        }

        uint256_t add(const uint256_t &other) const
        {
            uint256_t result(0);
            unsigned __int128 carry = 0;
            for (int i = 3; i >= 0; --i)
            {
                unsigned __int128 sum = (unsigned __int128)limbs[i] + other.limbs[i] + carry;
                result.limbs[i] = (uint64_t)sum;
                carry = sum >> 64;
            }
            // Note: Does not handle overflow if final carry > 0.
            return result;
        }

        uint256_t subtract(const uint256_t &other) const
        {
            if (*this < other)
                throw std::runtime_error("uint256_t::subtract results in negative value");
            uint256_t result(0);
            uint64_t borrow = 0;
            for (int i = 3; i >= 0; --i)
            {
                unsigned __int128 val_a = limbs[i];
                unsigned __int128 val_b = other.limbs[i];
                unsigned __int128 temp_borrow = borrow;         // Capture borrow from previous limb
                borrow = (val_b + temp_borrow > val_a) ? 1 : 0; // Check if we need to borrow for current limb
                result.limbs[i] = (uint64_t)(val_a - val_b - temp_borrow);
            }
            return result;
        }
    };

    // Difficulty constants
    const int64_t TARGET_BLOCK_TIME_SECONDS = 120;
    const uint64_t DIFFICULTY_WINDOW_BLOCKS = 72;
    const uint64_t DIFFICULTY_CUT_BLOCKS = 6;   // Total 2*6=12 blocks cut from window ends.
    const uint64_t DIFFICULTY_CLAMP_FACTOR = 2; // Max difficulty change: target can be scaled by 1/X or X.

    // Helper to convert hex char to int (needed for hex_str_to_hash)
    unsigned char hex_char_to_dec(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        throw std::runtime_error("Invalid hex character in target string");
    }

    // Helper to convert hex string to crypto::hash
    crypto::hash hex_str_to_hash(const std::string &hex_str)
    {
        if (hex_str.length() != 64)
            throw std::runtime_error("Hex string for hash must be 64 chars");
        crypto::hash h{}; // Zero-initialize
        unsigned char *hash_bytes = reinterpret_cast<unsigned char *>(h.data);
        for (size_t i = 0; i < 32; ++i)
        {
            hash_bytes[i] = (hex_char_to_dec(hex_str[2 * i]) << 4) | hex_char_to_dec(hex_str[2 * i + 1]);
        }
        return h;
    }

    // Define Genesis and Max targets using const char* and converting to uint256_t
    const uint256_t GENESIS_TARGET_U256 = uint256_t(hex_str_to_hash("000ffff000000000000000000000000000000000000000000000000000000000"));
    const uint256_t MAX_TARGET_U256 = uint256_t(hex_str_to_hash("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    const uint256_t MIN_TARGET_U256 = uint256_t(1); // Smallest non-zero target

    static crypto::hash calculate_target(SimpleLMDB &db)
    {
        uint64_t current_height = 0;
        try
        {
            current_height = db.count_fast("blocks");
        }
        catch (const std::runtime_error &)
        { // Likely "Failed to get stats" if table "blocks" doesn't exist
            return GENESIS_TARGET_U256.to_hash();
        }

        if (current_height == 0)
        {
            return GENESIS_TARGET_U256.to_hash();
        }

        uint64_t N = DIFFICULTY_WINDOW_BLOCKS;
        uint64_t cut = DIFFICULTY_CUT_BLOCKS;
        if (current_height < N)
        { // Not enough blocks for full window
            N = current_height;
            cut = 0; // No cut for very short windows
        }
        if (N == 0 && current_height > 0)
            N = 1; // Should not happen if current_height > 0
        if (N < 1 + 2 * cut)
        {            // Window too small for cut, or N=0/1
            cut = 0; // Disable cut if window is smaller than cut amounts + 1
        }

        std::vector<uint64_t> timestamps;
        std::vector<uint256_t> targets_u256;
        timestamps.reserve(N);
        targets_u256.reserve(N);

        crypto::hash current_block_id_hash;
        crypto::hash zero_hash_for_comparison;
        std::memset(zero_hash_for_comparison.data, 0, sizeof(zero_hash_for_comparison)); // Assumes default ctor makes zero hash
                                                                                         // If not, std::memset(zero_hash_for_comparison.data, 0, sizeof(zero_hash_for_comparison.data));

        try
        {
            std::string tip_id_str = db.get("tips", "0");
            if (tip_id_str.size() != sizeof(current_block_id_hash.data))
            { // Check size against raw array
                throw std::runtime_error("Invalid tip_id size from DB");
            }
            std::memcpy(current_block_id_hash.data, tip_id_str.data(), sizeof(current_block_id_hash.data));
        }
        catch (const std::runtime_error &e)
        {                                         // "Key not found" or other DB error
            return GENESIS_TARGET_U256.to_hash(); // Cannot get tip, fallback to genesis
        }

        for (uint64_t i = 0; i < N; ++i)
        {
            if (current_block_id_hash == zero_hash_for_comparison)
            { // Reached nominal pre-genesis state
                break;
            }

            std::string block_blob_str;
            try
            {
                block_blob_str = db.get("blocks", std::string(reinterpret_cast<const char *>(current_block_id_hash.data), sizeof(current_block_id_hash.data)));
            }
            catch (const std::runtime_error &e)
            { // Block not found
                break;
            }

            // The block::deserialize_block function has std::cout, which is not ideal for library code.
            // Also, deserializing the full block is inefficient if only the header is needed.
            // A production system should have a way to fetch/deserialize only the header.
            block b = block::deserialize_block(block_blob_str);

            timestamps.push_back(b.hdr.timestamp);
            targets_u256.push_back(uint256_t(b.hdr.target));

            if (b.hdr.tip_ids.empty())
            { // Reached actual genesis block (no parents)
                break;
            }
            current_block_id_hash = b.hdr.tip_ids[0]; // Assume first tip_id is the main chain parent
        }

        // Update N to actual number of blocks fetched
        N = timestamps.size();
        if (N <= 1 + 2 * cut)
        { // Not enough data for cut, or only 1 block (or 0 if error)
            if (targets_u256.empty())
                return GENESIS_TARGET_U256.to_hash(); // No blocks read
            return targets_u256[0].to_hash();         // Return target of the latest block (first in list as we iterate backwards)
        }

        // Data is currently newest-to-oldest. Reverse to make it oldest-to-newest.
        std::reverse(timestamps.begin(), timestamps.end());
        std::reverse(targets_u256.begin(), targets_u256.end());

        std::vector<uint64_t> sorted_timestamps = timestamps; // Copy for sorting
        std::sort(sorted_timestamps.begin(), sorted_timestamps.end());

        uint64_t actual_start_time = sorted_timestamps[cut];
        uint64_t actual_end_time = sorted_timestamps[N - 1 - cut];

        uint64_t time_span_actual = actual_end_time - actual_start_time;
        uint64_t num_blocks_for_span = N - 2 * cut;

        if (num_blocks_for_span == 0)
        {                                         // Should be caught by N <= 1 + 2*cut already
            return targets_u256.back().to_hash(); // Target of newest block in (chronological) window
        }

        if (time_span_actual == 0)
        {                         // Avoid division by zero; can happen if timestamps are identical
            time_span_actual = 1; // Makes difficulty very high
        }

        uint64_t time_span_expected = num_blocks_for_span * TARGET_BLOCK_TIME_SECONDS;

        // Basis for new target: target of the last block in the (chronological) window.
        uint256_t last_target_in_window = targets_u256.back();

        uint256_t new_target_u256 = last_target_in_window.multiply(time_span_actual);
        new_target_u256 = new_target_u256.divide(time_span_expected);

        // Clamp 1: Not above MAX_TARGET (easiest)
        if (MAX_TARGET_U256 < new_target_u256)
        {
            new_target_u256 = MAX_TARGET_U256;
        }

        // Clamp 2: Not below MIN_TARGET (e.g. 1, hardest practical)
        if (new_target_u256 < MIN_TARGET_U256)
        {
            new_target_u256 = MIN_TARGET_U256;
        }

        // Clamp 3: Relative change limit
        if (DIFFICULTY_CLAMP_FACTOR > 0)
        { // Allow disabling clamp if factor is 0
            uint256_t min_adj_target = last_target_in_window.divide(DIFFICULTY_CLAMP_FACTOR);
            uint256_t max_adj_target = last_target_in_window.multiply(DIFFICULTY_CLAMP_FACTOR);

            // Ensure min_adj_target is not below absolute MIN_TARGET
            if (min_adj_target < MIN_TARGET_U256)
                min_adj_target = MIN_TARGET_U256;
            // Ensure max_adj_target is not above absolute MAX_TARGET
            if (MAX_TARGET_U256 < max_adj_target)
                max_adj_target = MAX_TARGET_U256;

            if (new_target_u256 < min_adj_target)
            {
                new_target_u256 = min_adj_target;
            }
            if (max_adj_target < new_target_u256)
            {
                new_target_u256 = max_adj_target;
            }
        }

        // Final check: ensure target is not zero after any clamping.
        if (new_target_u256.is_zero())
        {
            new_target_u256 = MIN_TARGET_U256; // Fallback to minimum if somehow it became zero.
        }

        return new_target_u256.to_hash();
    }

    static block mine(SimpleLMDB &db, const crypto::public_key& miner_reward_address)
    {
        block candidate_block;
        header& hdr = candidate_block.hdr; // Use a reference for convenience

        // 1. Initialize Block Header (Partial)
        hdr.ver = 2; 
        hdr.timestamp = static_cast<uint64_t>(std::time(nullptr));
        hdr.target = calculate_target(db); // Calculate the difficulty target for this block
        hdr.nonce = 0; // Initial nonce for mining

        uint64_t current_block_height = 0;
        try {
            current_block_height = db.count_fast("blocks");
        } catch (const std::runtime_error&) { /* current_block_height remains 0 if table doesn't exist */ }

        if (current_block_height > 0) {
            try {
                std::string tip_id_str = db.get("tips", "0"); 
                if (tip_id_str.size() != sizeof(crypto::hash().data)) {
                     throw std::runtime_error("Invalid tip_id size from DB for key '0'");
                }
                crypto::hash tip_hash;
                std::memcpy(tip_hash.data, tip_id_str.data(), sizeof(tip_hash.data));
                hdr.tip_ids.push_back(tip_hash);
            } catch (const std::runtime_error& e) {
                throw std::runtime_error("Fatal: Failed to get tip for mining (height " + std::to_string(current_block_height) + "): " + std::string(e.what()));
            }
        }
        // If current_block_height is 0, hdr.tip_ids remains empty (genesis block case).

        // The 'seed' in the header is part of the data hashed for PoW.
        // The RandomX *key* for initializing the cache is fixed in header::calculate_header_id.
        const char header_pow_data_seed_str[] = "TXE_PoW_Data_Seed"; // Arbitrary string
        crypto::cn_fast_hash(header_pow_data_seed_str, sizeof(header_pow_data_seed_str) - 1, hdr.seed);


        // 2. Select Transactions from Mempool
        std::vector<tx>& selected_txs = candidate_block.txlist; // Use a reference
        uint64_t total_fees = 0;
        const size_t MAX_TX_PER_BLOCK = 4096;
        
        auto key_image_less = [](const crypto::key_image& lhs, const crypto::key_image& rhs){return std::memcmp(lhs.data, rhs.data, sizeof(lhs.data)) < 0;};
        std::set<crypto::key_image, decltype(key_image_less)> block_key_images_check(key_image_less); 
        
        try {
            std::vector<std::string> mempool_tx_blobs = db.get_all("mempool");
            std::cout << "Mempool size: " << mempool_tx_blobs.size() << " transactions." << std::endl;

            for (const auto& tx_blob_str : mempool_tx_blobs) {
                if (selected_txs.size() >= MAX_TX_PER_BLOCK) {
                    std::cout << "Reached max transactions per block (" << MAX_TX_PER_BLOCK << ")." << std::endl;
                    break;
                }

                tx t = tx::deserialize_tx(tx_blob_str);
                
                bool key_image_conflict_in_block = false;
                for (const auto& in : t.vin) {
                    if (block_key_images_check.count(in.image)) {
                        key_image_conflict_in_block = true;
                        std::cerr << "Skipping tx due to key image conflict within this block." << std::endl;
                        break;
                    }
                }
                if (key_image_conflict_in_block) continue; 

                if (t.ver(db, true, true, true)) { // Check semantics, signature, and inputs (key images on chain)
                    selected_txs.push_back(t);
                    total_fees += t.fee;
                    for (const auto& in : t.vin) {
                        block_key_images_check.insert(in.image);
                    }
                     std::cout << "Added valid tx to block, fee: " << t.fee << std::endl;
                } else {
                    std::cerr << "Transaction verification failed, not including in block." << std::endl;
                    // Optionally, remove invalid tx from mempool here
                    crypto::hash invalid_tx_hash;
                    crypto::cn_fast_hash(tx_blob_str.data(), tx_blob_str.size(), invalid_tx_hash);
                    db.del("mempool", std::string(reinterpret_cast<const char*>(invalid_tx_hash.data), sizeof(invalid_tx_hash.data)));
                }
            }
        } catch (const std::runtime_error& e) {
            std::cerr << "Warning: Error reading mempool (continuing with current selection): " << e.what() << std::endl;
        }
        std::cout << "Selected " << selected_txs.size() << " transactions from mempool. Total fees: " << total_fees << std::endl;

        // 3. Create Coinbase Transaction
        tx& miner_tx = candidate_block.miner_tx; // Use a reference
        miner_tx.version = hdr.ver;
        uint64_t block_reward_val = get_block_reward(db);
        uint64_t coinbase_amount = block_reward_val + total_fees;
        std::cout << "Block reward: " << block_reward_val << ", Total coinbase: " << coinbase_amount << std::endl;


        tx_input coinbase_in;
        crypto::hash height_hash_for_ki;
        uint64_t next_block_height = current_block_height; // For 0-indexed height used in KI
        crypto::cn_fast_hash(&next_block_height, sizeof(next_block_height), height_hash_for_ki);
        std::memcpy(coinbase_in.image.data, height_hash_for_ki.data, sizeof(coinbase_in.image.data));
        miner_tx.vin.push_back(coinbase_in);
        
        if (block_key_images_check.count(coinbase_in.image)) {
            // Extremely unlikely, but defensive check for coinbase KI collision with a mempool tx
            throw std::runtime_error("Fatal: Coinbase key image conflicts with a selected transaction's key image.");
        }
        block_key_images_check.insert(coinbase_in.image);

        tx_output coinbase_out;
        coinbase_out.ephemeral_pub_key = miner_reward_address; 
        miner_tx.vout.push_back(coinbase_out);
        
        miner_tx.fee = 0; // Coinbase tx has no explicit fee
        // miner_tx.ecdh_info is sized and filled by tx::make

        // Prepare arguments for tx::make for coinbase
        std::vector<rct::ctkey> inSk_cb; // No real inputs for coinbase
        std::vector<rct::ctkey> inPk_cb; // No real inputs for coinbase
        rct::keyV destinations_cb = {rct::pk2rct(miner_reward_address)};
        std::vector<uint64_t> inAmounts_cb = {}; // No input amounts
        std::vector<uint64_t> outAmounts_cb = {coinbase_amount};
        
        rct::keyV amount_keys_cb(1); // One output, so one amount key (mask for ecdh)
        // For coinbase, the amount is known, but we still generate a mask for ecdhInfo.
        // tx::make for coinbase sets the ecdh amount key to zero if is_coinbase=true.
        // However, we still need a placeholder for the amount_keys vector.
        amount_keys_cb[0] = rct::skGen(); // This will be overridden to zero by tx::make for coinbase actual amount component.

        hw::device& hwdev = hw::get_device("default");

        try {
             std::cout << "Generating coinbase transaction..." << std::endl;
            miner_tx.signature = miner_tx.make(
                inSk_cb, inPk_cb, destinations_cb,
                inAmounts_cb, outAmounts_cb, amount_keys_cb,
                0, hwdev, db, true // mixin = 0, is_coinbase = true
            );
        } catch (const std::exception& e) {
            throw std::runtime_error("Fatal: Failed to create coinbase transaction's RingCT signature: " + std::string(e.what()));
        }
        
        if (miner_tx.signature.outPk.empty()) { // tx::make should populate this
             throw std::runtime_error("Fatal: Coinbase tx.make did not produce outPk for commitment.");
        }
        if (miner_tx.signature.ecdhInfo.empty()) { // tx::make should populate this
            throw std::runtime_error("Fatal: Coinbase tx.make did not produce ecdhInfo.");
        }

        miner_tx.vout[0].commitment = miner_tx.signature.outPk[0].mask; // The commitment C = H(k_s G + a H)
        miner_tx.ecdh_info = miner_tx.signature.ecdhInfo; // Copy ecdhInfo (should be size 1)


        // 4. Calculate Merkle Root (now that all transactions are finalized)
        hdr.merkle_root = candidate_block.create_merkle_root();
        std::cout << "Merkle root calculated." << std::endl;

        // 5. Perform Proof-of-Work
        std::cout << "Starting Proof-of-Work for target..." << std::endl; // Can print target hex here
        // The header::calculate_header_id method now performs the mining loop.
        // It needs the difficulty target, which is already set in hdr.target.
        // It will update hdr.nonce and hdr.header_id.
        // The output parameter can be the same as hdr.header_id.
        hdr.calculate_header_id(hdr.header_id, hdr.target); 
        
        std::cout << "Block Mined! Nonce: " << hdr.nonce << std::endl;
        // Can print hdr.header_id hex here

        // The candidate_block is now complete.
        return candidate_block;
    }
}
#endif