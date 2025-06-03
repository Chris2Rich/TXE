#include <wallet.h>
#include <tx.h>
#include <block.h>
#include <db.h>
#include <mining.h>

#include <iostream>
#include <string>
#include <iomanip>
#include <cassert>
#include <vector>

#include <ringct/rctTypes.h>
#include <crypto/crypto.h>
#include <device/device.hpp>

template <typename T> // T should be crypto::public_key or crypto::secret_key
bool hex_to_key(const std::string &hex_str, T &key_obj)
{
    if (hex_str.length() != 64)
        return false;
    unsigned char *key_data = reinterpret_cast<unsigned char *>(key_obj.data);
    for (size_t i = 0; i < 32; ++i)
    {
        std::string byte_str = hex_str.substr(i * 2, 2);
        if (!isxdigit(byte_str[0]) || !isxdigit(byte_str[1]))
            return false;
        key_data[i] = static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16));
    }
    return true;
}

std::string key_to_hex(const rct::key &key_obj)
{
    std::stringstream ss;
    // rct::key uses .bytes instead of .data
    const unsigned char *key_data = reinterpret_cast<const unsigned char *>(key_obj.bytes);
    for (size_t i = 0; i < sizeof(key_obj.bytes); ++i) // or simply 32, as rct::key is fixed size
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_data[i]);
    }
    return ss.str();
}

// Helper to print keys (for debugging)
template <typename T>
std::string key_to_hex(const T &key_obj)
{
    std::stringstream ss;
    const unsigned char *key_data = reinterpret_cast<const unsigned char *>(key_obj.data);
    for (size_t i = 0; i < sizeof(key_obj.data); ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)key_data[i];
    }
    return ss.str();
}

// Helper: Creates a mock spendable output and stores it in the DB.
// Returns the one-time secret key (x) and commitment mask (a) needed to spend it.
std::pair<rct::key, rct::key> create_mock_spendable_output_for_wallet(
    TXE::SimpleLMDB &db,
    size_t global_output_idx,
    const TXE::WalletKeys &recipient_wallet, // Wallet that will "own" this output
    uint64_t amount,
    rct::ctkey &generated_ctkey // Output: P (one-time pubkey), C (commitment) that goes on chain
)
{
    crypto::secret_key tx_ephemeral_sk_r; // Ephemeral secret key for this "fake" incoming tx
    crypto::public_key tx_ephemeral_pk_R; // R = rG
    crypto::generate_keys(tx_ephemeral_pk_R, tx_ephemeral_sk_r);

    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(recipient_wallet.spend_pub, tx_ephemeral_sk_r, derivation))
    {
        throw std::runtime_error("Test setup: Failed to generate derivation for mock output");
    }

    crypto::public_key one_time_output_pk_P; // P_out = Hs(derivation || idx)G + B_spend
    if (!crypto::derive_public_key(derivation, 0 /*output index in this fake tx*/, recipient_wallet.spend_pub, one_time_output_pk_P))
    {
        throw std::runtime_error("Test setup: Failed to derive public key for mock output");
    }
    generated_ctkey.dest = rct::pk2rct(one_time_output_pk_P); // Store P

    // Wallet needs to derive its one-time secret key x for this output P
    crypto::secret_key one_time_output_sk_x;
    crypto::derive_secret_key(derivation, 0, recipient_wallet.spend_sec, one_time_output_sk_x);

    // Create commitment C = aG + amount*H
    rct::key commitment_mask_a = rct::skGen();                     // Blinding factor 'a'
    generated_ctkey.mask = rct::commit(amount, commitment_mask_a); // C = aG + amountH (using rct::commit)

    // Store P and C in the DB's numeric index table
    std::string ctkey_blob;
    ctkey_blob.append(reinterpret_cast<const char *>(generated_ctkey.mask.bytes), 32); // Commitment C
    ctkey_blob.append(reinterpret_cast<const char *>(generated_ctkey.dest.bytes), 32); // Public Key P
    db.put("output_indexes", std::to_string(global_output_idx), ctkey_blob);
    db.put("outputs", std::to_string(global_output_idx), "TEST");

    // Update global count (simplified)
    uint64_t current_count = 0;
    try
    {
        current_count = db.count_fast("output_indexes");
    }
    catch (...)
    { /*ignore if table empty*/
    }
    // This isn't strictly needed if count_fast works on output_index directly.
    // But if you had a separate metadata counter:
    // db.put("metadata", "@GLOBAL_OUTPUT_COUNT", std::to_string(current_count));
    return {rct::sk2rct(one_time_output_sk_x), commitment_mask_a}; // Return x and a
}

void test_transactions(TXE::SimpleLMDB &db, hw::device &hwdev)
{
    std::cout << "\n--- Starting Transaction Tests ---" << std::endl;

    // --- ARRANGE ---

    // 1. Wallets
    TXE::WalletKeys sender_wallet = TXE::WalletKeys::generate(); // Using random for simplicity here
    TXE::WalletKeys recipient_wallet = TXE::WalletKeys::generate();
    std::cout << "Sender Spend Pub: " << key_to_hex(sender_wallet.spend_pub) << std::endl;
    std::cout << "Recipient Spend Pub: " << key_to_hex(recipient_wallet.spend_pub) << std::endl;

    // 2. Create mock spendable inputs for sender in DB
    uint64_t input1_amount = 10000;
    rct::ctkey input1_pk_on_chain; // P, C
    auto [input1_sk_x, input1_mask_a] = create_mock_spendable_output_for_wallet(
        db, 0, sender_wallet, input1_amount, input1_pk_on_chain);
    std::cout << "Created mock spendable input 0 (global_idx 0) for sender with amount " << input1_amount << std::endl;

    uint64_t input2_amount = 7000;
    rct::ctkey input2_pk_on_chain;
    auto [input2_sk_x, input2_mask_a] = create_mock_spendable_output_for_wallet(
        db, 1, sender_wallet, input2_amount, input2_pk_on_chain);
    std::cout << "Created mock spendable input 1 (global_idx 1) for sender with amount " << input2_amount << std::endl;

    // Create some dummy outputs to act as decoys (owned by someone else)
    rct::ctkey dummy_decoy_ctkey;
    TXE::WalletKeys dummy_owner = TXE::WalletKeys::generate();
    std::cout << "Creating decoy outputs..." << std::endl;
    for (int i = 2; i < 17; i++)
    {
        create_mock_spendable_output_for_wallet(db, i, dummy_owner, 500 + (i * 100), dummy_decoy_ctkey);
    }
    std::cout << "Created 15 additional outputs for decoys " << std::endl;

    // --- TEST 1: Correct Transaction (1 input, 2 outputs) ---
    std::cout << "\n--- Test 1: Correct Transaction ---" << std::endl;
    TXE::tx correct_tx;
    correct_tx.version = 1;                        // Your CLSAG+BP version
    correct_tx.signature.type = rct::RCTTypeCLSAG; // Ensure correct type for make

    // Prepare inputs for tx.make
    std::vector<rct::ctkey> correct_in_sk_vec;
    std::vector<rct::ctkey> correct_in_pk_vec;
    std::vector<uint64_t> correct_in_amounts_vec;

    // Using input1
    TXE::tx_input tx_in1_struct;
    tx_in1_struct.amount = input1_amount; // For wallet's internal tracking
    crypto::generate_key_image(reinterpret_cast<const crypto::public_key &>(input1_pk_on_chain.dest),
                               reinterpret_cast<const crypto::secret_key &>(input1_sk_x),
                               tx_in1_struct.image);
    tx_in1_struct.key_offsets = {0}; // Global index of the input
    correct_tx.vin.push_back(tx_in1_struct);

    correct_in_sk_vec.push_back({input1_sk_x, input1_mask_a});
    correct_in_pk_vec.push_back(input1_pk_on_chain);
    correct_in_amounts_vec.push_back(input1_amount);

    // Prepare outputs for tx.make
    uint64_t amount_to_recipient = 6000;
    uint64_t fee = 500;
    uint64_t change_to_sender = input1_amount - amount_to_recipient - fee;

    std::vector<std::pair<crypto::public_key, uint64_t>> conceptual_outputs;
    conceptual_outputs.push_back({recipient_wallet.spend_pub, amount_to_recipient});
    if (change_to_sender > 0)
    {
        conceptual_outputs.push_back({sender_wallet.spend_pub, change_to_sender});
    }
    correct_tx.vout.resize(conceptual_outputs.size()); // Pre-size

    rct::keyV destinations_for_make(conceptual_outputs.size());
    rct::keyV amount_keys_for_make(conceptual_outputs.size());
    std::vector<uint64_t> out_amounts_for_make(conceptual_outputs.size());

    crypto::secret_key tx_secret_key_r_correct;
    crypto::public_key tx_public_key_R_correct;
    crypto::generate_keys(tx_public_key_R_correct, tx_secret_key_r_correct);

    for (size_t i = 0; i < conceptual_outputs.size(); ++i)
    {
        out_amounts_for_make[i] = conceptual_outputs[i].second;
        crypto::key_derivation derivation;
        crypto::generate_key_derivation(conceptual_outputs[i].first, tx_secret_key_r_correct, derivation);
        crypto::derive_public_key(derivation, i, conceptual_outputs[i].first, reinterpret_cast<crypto::public_key &>(destinations_for_make[i]));
        crypto::ec_scalar s;
        crypto::derivation_to_scalar(derivation, i, s);
        std::memcpy(amount_keys_for_make[i].bytes, s.data, sizeof(s.data));
    }
    correct_tx.fee = fee;

    try
    {
        correct_tx.signature = correct_tx.make(
            correct_in_sk_vec, correct_in_pk_vec, destinations_for_make,
            correct_in_amounts_vec, out_amounts_for_make, amount_keys_for_make,
            3 /*mixin*/, hwdev, db);
        // Populate vout and ecdhInfo from signature
        for (size_t i = 0; i < correct_tx.vout.size(); ++i)
        {
            correct_tx.vout[i].ephemeral_pub_key = reinterpret_cast<const crypto::public_key &>(correct_tx.signature.outPk[i].dest);
            correct_tx.vout[i].commitment = correct_tx.signature.outPk[i].mask;
        }
        correct_tx.ecdh_info = correct_tx.signature.ecdhInfo;

        std::cout << "Correct TX created. Verifying..." << std::endl;
        bool verified_correct = correct_tx.ver(db, true, true, true);
        assert(verified_correct && "Correctly created transaction FAILED verification!");
        std::cout << "SUCCESS: Correct transaction verified." << std::endl;

        // Add key image to DB for next test
        db.put("key_images", std::string(reinterpret_cast<const char *>(correct_tx.vin[0].image.data), 32), "spent_in_test1");
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error in Correct Transaction Test: " << e.what() << std::endl;
        assert(false && "Correct transaction test threw exception.");
    }

    // --- TEST 2: Malformed Transaction - Tamper with Bulletproof 'A' component ---
    std::cout << "\n--- Test 2: Malformed Transaction (Tampered Bulletproof.A) ---" << std::endl;
    if (!correct_tx.signature.p.bulletproofs.empty())
    {
        TXE::tx tampered_tx_bp = correct_tx; // Make a copy
        // Tamper: Flip a byte in the A component of the first (and only) bulletproof
        if (!(tampered_tx_bp.signature.p.bulletproofs[0].A == rct::zero()))
        { // Avoid making it zero if it wasn't
            tampered_tx_bp.signature.p.bulletproofs[0].A.bytes[0] ^= 0xFF;
        }
        else
        { // If it was zero, make it non-zero
            tampered_tx_bp.signature.p.bulletproofs[0].A.bytes[0] = 0x01;
        }

        std::cout << "Tampered BP.A. Verifying..." << std::endl;
        bool verified_tampered_bp = tampered_tx_bp.ver(db, true, true, true);
        assert(!verified_tampered_bp && "Transaction with tampered Bulletproof.A unexpectedly VERIFIED!");
        if (!verified_tampered_bp)
        {
            std::cout << "SUCCESS: Transaction with tampered Bulletproof.A correctly FAILED verification." << std::endl;
        }
    }
    else
    {
        std::cout << "SKIPPING Test 2: No bulletproofs in correct_tx to tamper with." << std::endl;
    }

    // --- TEST 3: Malformed Transaction - Tamper with CLSAG 's' component ---
    std::cout << "\n--- Test 3: Malformed Transaction (Tampered CLSAG.s) ---" << std::endl;
    if (!correct_tx.signature.p.CLSAGs.empty() && !correct_tx.signature.p.CLSAGs[0].s.empty())
    {
        TXE::tx tampered_tx_clsag_s = correct_tx;                        // Make a copy
        tampered_tx_clsag_s.signature.p.CLSAGs[0].s[0].bytes[0] ^= 0xFF; // Flip a byte

        std::cout << "Tampered CLSAG.s. Verifying..." << std::endl;
        bool verified_tampered_clsag_s = tampered_tx_clsag_s.ver(db, true, true, true);
        assert(!verified_tampered_clsag_s && "Transaction with tampered CLSAG.s unexpectedly VERIFIED!");
        if (!verified_tampered_clsag_s)
        {
            std::cout << "SUCCESS: Transaction with tampered CLSAG.s correctly FAILED verification." << std::endl;
        }
    }
    else
    {
        std::cout << "SKIPPING Test 3: No CLSAGs or s values in correct_tx to tamper with." << std::endl;
    }

    // --- TEST 4: Malformed Transaction - Tamper with message input to CLSAG verification ---
    // This tests if get_message_for_clsag is sensitive. We tamper the *original tx data*
    // so get_message_for_clsag computes a different hash than what was signed.
    std::cout << "\n--- Test 4: Malformed Transaction (Tampered Tx Fee -> Message Mismatch) ---" << std::endl;
    TXE::tx tampered_tx_fee = correct_tx; // Copy the original valid tx
    tampered_tx_fee.fee += 100;           // Change the fee. This will alter the prefix hash.
                                          // The signature is still the one generated for the *original* fee.

    std::cout << "Tampered tx.fee (message for CLSAG will mismatch). Verifying..." << std::endl;
    bool verified_tampered_fee = tampered_tx_fee.ver(db, true, true, true); // ver uses this tampered_tx_fee to recalc message
    assert(!verified_tampered_fee && "Transaction with tampered fee unexpectedly VERIFIED!");
    if (!verified_tampered_fee)
    {
        std::cout << "SUCCESS: Transaction with tampered fee correctly FAILED verification." << std::endl;
    }

    // --- TEST 5: Malformed Transaction - Spent Key Image ---
    std::cout << "\n--- Test 5: Malformed Transaction (Spent Key Image) ---" << std::endl;
    // We use the 'correct_tx' which already had its key image recorded as spent in Test 1.
    // No need to tamper with the signature itself for this test.
    // The `ver` function's key image check should catch this.
    std::cout << "Attempting to verify transaction with already spent key image..." << std::endl;
    bool verified_spent_ki = correct_tx.ver(db, true, true, true); // Semantic and sig checks should pass, but KI check should fail
    assert(!verified_spent_ki && "Transaction with spent key image unexpectedly VERIFIED (or an earlier check failed this path)!");
    if (!verified_spent_ki)
    {
        std::cout << "SUCCESS: Transaction with spent key image correctly FAILED verification." << std::endl;
    }

    // TODO: Add more malformation tests:
    // - Tamper pseudoOuts (rv.p.pseudoOuts[0]) -> CLSAG should fail
    // - Tamper mixRing member (rv.mixRing[0][0].dest) -> CLSAG should fail
    // - Incorrect number of inputs/outputs vs signature components
    // - Amounts in Bulletproof don't balance (harder to set up, `make` might catch it, or `verBulletproof` might)

    std::cout << "\n--- Transaction Tests Finished ---" << std::endl;
}

int test(int argc, char *argv[])
{
    std::string db_path = "./lmdb_data";
    std::filesystem::remove_all(db_path); // Clean previous test run
    TXE::SimpleLMDB db(db_path);
    hw::device &hwdev = hw::get_device("default");

    // Create necessary DBIs
    MDB_txn *setup_txn;
    mdb_txn_begin(db.env, nullptr, 0, &setup_txn);
    db.get_dbi("blocks", setup_txn);         // header_id : serialized block data
    db.get_dbi("tips", setup_txn);           // numeric : header_id
    db.get_dbi("key_images", setup_txn);     // key image : hash of tx that first included
    db.get_dbi("transactions", setup_txn);   // hash of tx : serialized tx data
    db.get_dbi("outputs", setup_txn);        // ephemeral key : serialized output data
    db.get_dbi("output_indexes", setup_txn); // numeric : [32-byte commitment mask | 32-byte destination public key] -- doesnt matter for consensus
    db.get_dbi("mempool", setup_txn);        // hash of tx : serialized tx data
    mdb_txn_commit(setup_txn);

    try
    {
        test_transactions(db, hwdev);
    }
    catch (const std::exception &e)
    {
        std::cerr << "EXCEPTION during tests: " << e.what() << std::endl;
        return 1;
    }
    std::filesystem::remove_all(db_path);
    return 0;
}

TXE::block create_deterministic_genesis_block(
    TXE::SimpleLMDB &db, // To store the genesis block and its output
    hw::device &hwdev,
    const crypto::secret_key &genesis_master_secret_key // The core secret key for determinism
)
{
    std::cout << "Creating deterministic genesis block..." << std::endl;

    // --- 1. Define Fixed Genesis Parameters ---
    const uint64_t GENESIS_TIMESTAMP = 1748810142;
    const std::string GENESIS_EXTRA_MESSAGE = "Genesis 1: 26-28";
    const uint64_t GENESIS_COINBASE_AMOUNT = 10000000; // 10000 TXE (3 decimal places)
    const uint32_t GENESIS_TX_VERSION = 1;             // Your CLSAG+BP tx version
    const uint32_t GENESIS_BLOCK_VERSION = 1;
    const uint64_t GENESIS_NONCE = 0; // Can be fixed or derived
    crypto::hash GENESIS_TARGET;
    const uint8_t value[32] = {
        0x00, 0x0f, 0xff, 0xf0,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00};
    std::memcpy(GENESIS_TARGET.data, value, 32);

    // --- 2. Derive Keys and Seeds from genesis_master_secret_key ---

    // Derive recipient keys for the genesis coinbase output
    crypto::secret_key genesis_recipient_spend_sk_derived;
    crypto::public_key genesis_recipient_spend_pk_derived;
    crypto::hash recipient_sk_hash;
    crypto::cn_fast_hash(&genesis_master_secret_key, sizeof(genesis_master_secret_key), recipient_sk_hash);
    genesis_recipient_spend_sk_derived = reinterpret_cast<const crypto::secret_key &>(recipient_sk_hash);
    crypto::secret_key_to_public_key(genesis_recipient_spend_sk_derived, genesis_recipient_spend_pk_derived);
    // For simplicity, let's make view key same as spend key for this derived recipient,
    // or derive it separately if needed for your wallet logic.
    // If you need a separate view key for the recipient to scan:
    crypto::hash view_key_seed_hash;
    crypto::cn_fast_hash(&genesis_master_secret_key, sizeof(genesis_master_secret_key), view_key_seed_hash);                 // Hash master sk
    crypto::secret_key genesis_recipient_view_sk_derived = reinterpret_cast<const crypto::secret_key &>(view_key_seed_hash); // Treat hash as sk
    crypto::public_key genesis_recipient_view_pk_derived;
    crypto::secret_key_to_public_key(genesis_recipient_view_sk_derived, genesis_recipient_view_pk_derived);

    // Derive keys for the dummy input of the coinbase transaction
    crypto::hash dummy_input_sk_seed_hash;
    char dummy_seed_modifier[] = "dummy_input";
    std::string dummy_input_seed_material = std::string(reinterpret_cast<const char *>(genesis_master_secret_key.data), sizeof(genesis_master_secret_key.data)) + dummy_seed_modifier;
    crypto::cn_fast_hash(dummy_input_seed_material.data(), dummy_input_seed_material.size(), dummy_input_sk_seed_hash);

    rct::ctkey genesis_dummy_inSk;
    genesis_dummy_inSk.dest = rct::sk2rct(reinterpret_cast<const crypto::secret_key &>(dummy_input_sk_seed_hash)); // x_in
    rct::skpkGen(genesis_dummy_inSk.dest, genesis_dummy_inSk.mask);                                                // P_in = x_in * G. Store P_in in mask for this dummy usage.
                                                                                                                   // Actually, ctkey is {dest, mask}. P_in (dest) and C_in (mask)
    rct::ctkey genesis_dummy_inPk;
    genesis_dummy_inPk.dest = genesis_dummy_inSk.mask; // P_in (public key part)
    genesis_dummy_inPk.mask = rct::identity();         // C_in (commitment to 0 amount with 0 mask for dummy)
                                                       // C = aG + mH. If a=0, m=0, C=0. If using identity() (0*G), it's fine.

    char header_seed_modifier[] = "The name of God is sacred";
    crypto::hash genesis_header_randomx_seed = crypto::cn_fast_hash(header_seed_modifier, 26);

    // --- 3. Create Genesis Coinbase Transaction (TXE::tx) ---
    TXE::tx coinbase_tx;
    coinbase_tx.version = GENESIS_TX_VERSION;
    coinbase_tx.fee = 0;
    coinbase_tx.signature.type = rct::RCTTypeCLSAG; // Set explicitly

    // a. Dummy Input (vin)
    TXE::tx_input dummy_input;
    dummy_input.amount = 0;
    crypto::generate_key_image(reinterpret_cast<const crypto::public_key &>(genesis_dummy_inPk.dest),
                               reinterpret_cast<const crypto::secret_key &>(genesis_dummy_inSk.dest),
                               dummy_input.image);
    dummy_input.key_offsets = {}; // No real previous outputs
    coinbase_tx.vin.push_back(dummy_input);

    // b. Output (vout) - will be mostly populated by `make`
    coinbase_tx.vout.resize(1); // One output for the genesis amount

    // c. Extra Data
    coinbase_tx.extra.assign(GENESIS_EXTRA_MESSAGE.begin(), GENESIS_EXTRA_MESSAGE.end());

    // d. Prepare parameters for tx::make
    std::vector<rct::ctkey> in_sk_vec = {genesis_dummy_inSk};
    std::vector<rct::ctkey> in_pk_vec = {genesis_dummy_inPk};
    std::vector<uint64_t> in_amounts_vec = {0};

    // Create the one-time output destination key for the genesis recipient
    crypto::secret_key tx_ephemeral_sk_r_genesis; // Ephemeral key for this genesis coinbase tx
    crypto::public_key tx_ephemeral_pk_R_genesis;
    // Derive tx ephemeral key deterministically too, so R is always the same for genesis
    crypto::hash genesis_tx_r_seed_hash;
    char tx_r_modifier[] = "genesis_tx_r";
    std::string tx_r_seed_material = std::string(reinterpret_cast<const char *>(genesis_master_secret_key.data), sizeof(genesis_master_secret_key.data)) + tx_r_modifier;
    crypto::cn_fast_hash(tx_r_seed_material.data(), tx_r_seed_material.size(), genesis_tx_r_seed_hash);
    tx_ephemeral_sk_r_genesis = reinterpret_cast<const crypto::secret_key &>(genesis_tx_r_seed_hash);
    crypto::secret_key_to_public_key(tx_ephemeral_sk_r_genesis, tx_ephemeral_pk_R_genesis);

    rct::keyV destinations_for_make(1);
    rct::keyV amount_keys_for_make(1);
    std::vector<uint64_t> out_amounts_for_make = {GENESIS_COINBASE_AMOUNT};

    crypto::key_derivation derivation_recipient;
    crypto::generate_key_derivation(genesis_recipient_spend_pk_derived, tx_ephemeral_sk_r_genesis, derivation_recipient);
    crypto::derive_public_key(derivation_recipient, 0, genesis_recipient_spend_pk_derived, reinterpret_cast<crypto::public_key &>(destinations_for_make[0]));

    crypto::ec_scalar scalar_for_ecdh;
    crypto::derivation_to_scalar(derivation_recipient, 0, scalar_for_ecdh);
    std::memcpy(amount_keys_for_make[0].bytes, scalar_for_ecdh.data, sizeof(scalar_for_ecdh.data));

    // e. Call tx::make
    std::cout << "   Making genesis coinbase signature..." << std::endl;
    coinbase_tx.signature = coinbase_tx.make(
        in_sk_vec, in_pk_vec, destinations_for_make,
        in_amounts_vec, out_amounts_for_make, amount_keys_for_make,
        0 /*mixin for genesis coinbase input*/, hwdev, db);

    // f. Populate coinbase_tx.vout and coinbase_tx.ecdh_info from the signature
    if (coinbase_tx.signature.outPk.size() != 1 || coinbase_tx.signature.ecdhInfo.size() != 1)
    {
        throw std::runtime_error("Genesis coinbase creation: outPk or ecdhInfo not correctly sized by genRctSimple.");
    }
    coinbase_tx.vout[0].ephemeral_pub_key = reinterpret_cast<const crypto::public_key &>(coinbase_tx.signature.outPk[0].dest);
    coinbase_tx.vout[0].commitment = coinbase_tx.signature.outPk[0].mask;
    // coinbase_tx.vout[0].opcodes = ""; // Already default
    coinbase_tx.ecdh_info = coinbase_tx.signature.ecdhInfo;

    std::cout << "   Genesis coinbase transaction created." << std::endl;

    // --- 4. Create Genesis Block Header (TXE::header) ---
    TXE::header genesis_header;
    genesis_header.ver = GENESIS_BLOCK_VERSION;
    genesis_header.timestamp = GENESIS_TIMESTAMP;
    genesis_header.nonce = GENESIS_NONCE;
    genesis_header.target = GENESIS_TARGET;
    genesis_header.tip_ids.clear(); // No parents

    // Merkle Root (only the coinbase tx)
    std::string miner_tx_blob = coinbase_tx.serialize_tx();
    crypto::cn_fast_hash(miner_tx_blob.data(), miner_tx_blob.size(), genesis_header.merkle_root);

    // RandomX seed for this block's header hash calculation
    genesis_header.seed = genesis_header_randomx_seed;

    // Calculate Header ID (PoW hash of the header)
    // The calculate_header_id in your block.cpp uses its own internal fixed seed for RandomX cache.
    // This is fine, as long as it's deterministic.
    std::cout << "   Calculating genesis block header ID..." << std::endl;
    genesis_header.calculate_header_id(genesis_header.header_id, GENESIS_TARGET);
    std::cout << "   Genesis block header ID calculated." << std::endl;

    // --- 5. Assemble Genesis Block (TXE::block) ---
    TXE::block genesis_block_obj;
    genesis_block_obj.hdr = genesis_header;
    genesis_block_obj.miner_tx = coinbase_tx;
    genesis_block_obj.txlist.clear(); // No other transactions

    std::cout << "Genesis block assembled." << std::endl;

    return genesis_block_obj;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        return 0;
    }

    if (std::string(argv[1]) == "runtests")
    {
        return test(argc, argv);
    }

    if (std::string(argv[1]) == "init")
    {
        TXE::SimpleLMDB db("./lmdb_data");
        std::filesystem::remove_all("./lmdb_data");
        MDB_txn *txn;
        if (mdb_txn_begin(db.env, nullptr, 0, &txn))
            throw std::runtime_error("Failed to begin init transaction");

        db.get_dbi("blocks", txn);         // header_id : serialized block data
        db.get_dbi("tips", txn);           // numeric : header_id
        db.get_dbi("key_images", txn);     // key image : hash of tx that first included
        db.get_dbi("transactions", txn);   // hash of tx : serialized tx data
        db.get_dbi("outputs", txn);        // ephemeral key : serialized output data
        db.get_dbi("output_indexes", txn); // numeric : [32-byte commitment mask | 32-byte destination public key] -- doesnt matter for consensus
        db.get_dbi("mempool", txn);        // hash of tx : serialized tx data

        if (mdb_txn_commit(txn))
            throw std::runtime_error("Failed to commit init transaction");

        std::cout << "LMDB initialized with tables: blocks, key_images, ring_members, transactions, outputs" << std::endl;

        crypto::secret_key genesis_key;
        std::string seed_string = "One Way!";
        crypto::hash seed_hash;
        crypto::cn_fast_hash(seed_string.data(), seed_string.length(), seed_hash);
        std::memcpy(genesis_key.data, seed_hash.data, sizeof(genesis_key.data));
        TXE::block genesis = create_deterministic_genesis_block(db, hw::get_device("default"), genesis_key);
        TXE::block::add_block_to_db(genesis, &db);
    }
    if (std::string(argv[1]) == "wallet")
    {
        // wallet create "filepath"
        if (std::string(argv[2]) == "create")
        {

            std::string pass;
            std::cout << "Input Password: ";
            std::cin >> pass;
            std::cout << std::endl;

            TXE::WalletKeys k = TXE::WalletKeys::generate();
            k.save(std::string(argv[3]), pass);
            std::cout << "wallet keys saved at: " << std::string(argv[3]) << std::endl;
        }
        // wallet list "filepath" password
        if (std::string(argv[2]) == "view")
        {

            std::string pass;
            std::cout << "Input Password: ";
            std::cin >> pass;
            std::cout << std::endl;

            TXE::WalletKeys k = TXE::WalletKeys::load(std::string(argv[3]), pass);

            std::cout << "wallet keys from: " << std::string(argv[3]) << std::endl;
            std::cout << "Spend Public Key: " << k.spend_pub << std::endl;
            std::cout << "Spend Secret Key: " << crypto::secret_key_explicit_print_ref{k.spend_sec} << std::endl;
            std::cout << "View Public Key:  " << k.view_pub << std::endl;
            std::cout << "View Secret Key:  " << crypto::secret_key_explicit_print_ref{k.view_sec} << std::endl;
        }
    }
    if (std::string(argv[1]) == "transact")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: ./TXE transact <wallet_filepath>" << std::endl;
            return 1;
        }
        std::string wallet_path = argv[2];
        std::string password;
        std::cout << "Enter wallet password: ";
        std::cin >> password; // Note: for passwords with spaces, consider std::getline

        TXE::WalletKeys sender_wallet;
        try
        {
            sender_wallet = TXE::WalletKeys::load(wallet_path, password);
            std::cout << "Wallet loaded successfully." << std::endl;
            std::cout << "Sender Spend PubKey: " << key_to_hex(sender_wallet.spend_pub) << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Failed to load wallet: " << e.what() << std::endl;
            return 1;
        }

        TXE::SimpleLMDB db("./lmdb_data");
        hw::device &hwdev = hw::get_device("default");

        // --- Get Owned Outputs by Calling WalletKeys::get_owned ---
        std::cout << "Scanning blockchain for spendable outputs... This may take some time if using block scan." << std::endl;
        std::vector<TXE::SpendableOutputInfo> owned_outputs; // TXE:: namespace for clarity
        try {
            owned_outputs = sender_wallet.get_owned(db); // This now calls your implemented get_owned
            std::cout << "Wallet sync complete." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error during wallet sync (get_owned call): " << e.what() << std::endl;
            return 1;
        }
        
        // Note: The local 'SpendableOutputInfo' struct definition previously here is removed,
        // as it's assumed to be globally available from an included header (e.g., wallet.h).

        if (owned_outputs.empty())
        {
            std::cout << "Wallet has no spendable outputs found on the blockchain." << std::endl;
            std::cerr << "Cannot create transaction with no spendable outputs." << std::endl;
            return 1; 
        }

        std::cout << "Wallet's spendable outputs (" << owned_outputs.size() << " found):" << std::endl;
        uint64_t total_owned_balance = 0;
        for (const auto &out : owned_outputs)
        {
            total_owned_balance += out.amount;
            // If get_owned uses block scanning, global_index might be an approximation.
            std::cout << "  - Amount: " << out.amount
                      << ", Global Index (approx if from block scan): " << out.global_index 
                      << ", P: " << key_to_hex(out.pk_on_chain.dest).substr(0, 10) << "..." << std::endl;
        }
        std::cout << "Total available balance: " << total_owned_balance << std::endl;

        // --- Gather Transaction Details ---
        int num_recipients;
        std::cout << "Enter number of recipients (distinct outputs): ";
        std::cin >> num_recipients;
         if (num_recipients <= 0) {
             std::cerr << "Error: Number of recipients must be a positive integer." << std::endl;
             return 1;
        }

        std::vector<std::pair<crypto::public_key, uint64_t>> conceptual_dests_amounts;
        uint64_t total_sending_to_recipients = 0;

        for (int i = 0; i < num_recipients; ++i)
        {
            std::string recipient_pk_hex;
            uint64_t amount_to_send;
            crypto::public_key recipient_pk;

            std::cout << "For recipient #" << i + 1 << ":" << std::endl;
            std::cout << "  Enter recipient public spend key (hex, 64 chars): ";
            std::cin >> recipient_pk_hex;
            if (!hex_to_key(recipient_pk_hex, recipient_pk))
            {
                std::cerr << "  Error: Invalid recipient public key format. Must be 64 hex characters." << std::endl;
                return 1;
            }
            std::cout << "  Enter amount to send to this recipient: ";
            std::cin >> amount_to_send;
            if (amount_to_send == 0)
            {
                std::cerr << "  Error: Amount cannot be zero." << std::endl;
                return 1;
            }

            conceptual_dests_amounts.push_back({recipient_pk, amount_to_send});
            total_sending_to_recipients += amount_to_send;
        }

        uint64_t fee;
        std::cout << "Enter transaction fee: ";
        std::cin >> fee;
        if (fee == 0) // Fee can be zero, but warn user
        {
            std::cout << "Warning: Using a zero fee. Transaction might not be prioritized by miners." << std::endl;
        }

        uint64_t total_required_for_tx = total_sending_to_recipients + fee;
        std::cout << "Total to cover (recipients + fee): " << total_required_for_tx << std::endl;

        if (total_owned_balance < total_required_for_tx)
        {
            std::cerr << "Error: Insufficient funds. Available: " << total_owned_balance
                      << ", Required: " << total_required_for_tx << std::endl;
            return 1;
        }

        // --- Select Inputs (strategy: use largest outputs first) ---
        std::sort(owned_outputs.begin(), owned_outputs.end(),
                  [](const TXE::SpendableOutputInfo &a, const TXE::SpendableOutputInfo &b) // Explicit TXE:: namespace
                  {
                      return a.amount > b.amount; // Sort descending by amount
                  });

        std::vector<TXE::SpendableOutputInfo> selected_inputs_info; // Explicit TXE:: namespace
        uint64_t current_input_sum = 0;
        for (const auto &owned_out_info : owned_outputs)
        {
            if (current_input_sum < total_required_for_tx)
            {
                selected_inputs_info.push_back(owned_out_info);
                current_input_sum += owned_out_info.amount;
            }
            else
            {
                break; // Enough inputs selected
            }
        }

        if (current_input_sum < total_required_for_tx)
        {
            std::cerr << "Error: Failed to select sufficient inputs even after initial balance check. (Available sum: " << current_input_sum << ")" << std::endl;
            return 1;
        }
        std::cout << "Selected " << selected_inputs_info.size() << " inputs with a total value of " << current_input_sum << std::endl;

        // --- Calculate Change and Add to Destinations ---
        uint64_t change_amount = current_input_sum - total_required_for_tx;
        if (change_amount > 0)
        {
            std::cout << "Change to be returned to sender: " << change_amount << std::endl;
            conceptual_dests_amounts.push_back({sender_wallet.spend_pub, change_amount});
        }

        // --- Construct the Transaction Object ---
        TXE::tx new_tx;
        new_tx.version = 1;
        new_tx.signature.type = rct::RCTTypeCLSAG; 
        new_tx.fee = fee;

        std::vector<rct::ctkey> in_sk_for_make; 
        std::vector<rct::ctkey> in_pk_for_make; 
        std::vector<uint64_t> in_amounts_for_make;

        std::cout << "Preparing transaction inputs for signing:" << std::endl;
        for (const auto &s_in_info : selected_inputs_info)
        {
            TXE::tx_input tx_in_struct;
            crypto::generate_key_image(
                reinterpret_cast<const crypto::public_key &>(s_in_info.pk_on_chain.dest), 
                reinterpret_cast<const crypto::secret_key &>(s_in_info.sk_x),            
                tx_in_struct.image);
            tx_in_struct.key_offsets = {s_in_info.global_index}; 

            new_tx.vin.push_back(tx_in_struct);
            in_sk_for_make.push_back({s_in_info.sk_x, s_in_info.mask_a});
            in_pk_for_make.push_back(s_in_info.pk_on_chain);
            in_amounts_for_make.push_back(s_in_info.amount);
            std::cout << "  Input: amt=" << s_in_info.amount
                      << ", idx (approx if from block scan)=" << s_in_info.global_index
                      << ", KI=" << key_to_hex(tx_in_struct.image).substr(0, 10) << "..." << std::endl;
        }

        new_tx.vout.resize(conceptual_dests_amounts.size()); 
        rct::keyV out_dest_pubkeys_for_make(conceptual_dests_amounts.size()); 
        rct::keyV out_amount_keys_for_make(conceptual_dests_amounts.size());  
        std::vector<uint64_t> out_amounts_for_make(conceptual_dests_amounts.size());

        crypto::secret_key tx_secret_key_r; 
        crypto::public_key tx_public_key_R; 
        crypto::generate_keys(tx_public_key_R, tx_secret_key_r);

        new_tx.extra.resize(sizeof(tx_public_key_R));
        memcpy(new_tx.extra.data(), tx_public_key_R.data, sizeof(tx_public_key_R));
        std::cout << "Tx public key R: " << key_to_hex(tx_public_key_R) << " (added to tx.extra)" << std::endl;

        std::cout << "Preparing transaction outputs for signing:" << std::endl;
        for (size_t i = 0; i < conceptual_dests_amounts.size(); ++i)
        {
            const auto &recipient_spend_pub_B = conceptual_dests_amounts[i].first; 
            out_amounts_for_make[i] = conceptual_dests_amounts[i].second;
            crypto::key_derivation derivation;
            if (!crypto::generate_key_derivation(recipient_spend_pub_B, tx_secret_key_r, derivation))
            {
                std::cerr << "Error: Failed to generate derivation for output #" << i << std::endl;
                return 1;
            }
            crypto::public_key one_time_output_pk_P; 
            if (!crypto::derive_public_key(derivation, i, recipient_spend_pub_B, one_time_output_pk_P))
            {
                std::cerr << "Error: Failed to derive public key P_out for output #" << i << std::endl;
                return 1;
            }
            out_dest_pubkeys_for_make[i] = rct::pk2rct(one_time_output_pk_P);
            crypto::ec_scalar scalar_for_ecdh_s_i; 
            crypto::derivation_to_scalar(derivation, i, scalar_for_ecdh_s_i);
            std::memcpy(out_amount_keys_for_make[i].bytes, scalar_for_ecdh_s_i.data, sizeof(scalar_for_ecdh_s_i.data));
            std::cout << "  Output #" << i << ": amt=" << out_amounts_for_make[i]
                      << ", To_B=" << key_to_hex(recipient_spend_pub_B).substr(0, 10) << "..."
                      << ", P_out=" << key_to_hex(out_dest_pubkeys_for_make[i]).substr(0, 10) << "..." << std::endl;
        }

        size_t num_decoys_available_on_chain = 0; 
        try
        {
            // This count is still used for determining mixin. It relies on 'output_indexes' table.
            num_decoys_available_on_chain = db.count_fast("output_indexes");
        }
        catch (...) { /* ignore if table empty or error */ }

        int mixin_count = 3; // Default desired mixin
        if (num_decoys_available_on_chain <= 1) 
        { 
            mixin_count = 0;
            if (num_decoys_available_on_chain > 0) { // Only print warning if there was at least 1 (the real one)
                 std::cout << "Warning: Not enough distinct outputs on chain for decoys (or 'output_indexes' table is too small). Mixin set to 0." << std::endl;
            } else {
                 std::cout << "Info: No outputs found in 'output_indexes' table. Mixin set to 0." << std::endl;
            }
        }
        else if (num_decoys_available_on_chain - 1 < static_cast<size_t>(mixin_count)) // -1 for the real input
        {
            mixin_count = num_decoys_available_on_chain - 1;
            std::cout << "Warning: Adjusting mixin to " << mixin_count 
                      << " due to limited number of decoy candidates in 'output_indexes' table." << std::endl;
        }
        std::cout << "Using mixin count: " << mixin_count << " (ring size " << mixin_count + 1 << ")" << std::endl;

        // --- Generate Signature and Finalize Transaction ---
        try
        {
            std::cout << "Calling tx.make() to generate signature..." << std::endl;
            new_tx.signature = new_tx.make(
                in_sk_for_make, in_pk_for_make, out_dest_pubkeys_for_make,
                in_amounts_for_make, out_amounts_for_make, out_amount_keys_for_make,
                mixin_count, hwdev, db);

            if (new_tx.signature.outPk.size() != new_tx.vout.size() ||
                new_tx.signature.ecdhInfo.size() != new_tx.vout.size())
            {
                std::cerr << "Error: Mismatch in sizes from tx.make signature components." << std::endl;
                std::cerr << "  outPk size: " << new_tx.signature.outPk.size() << " vs vout size: " << new_tx.vout.size() << std::endl;
                std::cerr << "  ecdhInfo size: " << new_tx.signature.ecdhInfo.size() << std::endl;
                return 1;
            }
            for (size_t i = 0; i < new_tx.vout.size(); ++i)
            {
                new_tx.vout[i].ephemeral_pub_key = reinterpret_cast<const crypto::public_key &>(new_tx.signature.outPk[i].dest); 
                new_tx.vout[i].commitment = new_tx.signature.outPk[i].mask;                       
            }
            new_tx.ecdh_info = new_tx.signature.ecdhInfo;

            std::cout << "Transaction constructed. Verifying transaction..." << std::endl;
            bool verified = new_tx.ver(db, true, true, true);

            if (verified)
            {
                std::cout << "SUCCESS: Transaction verified." << std::endl;
                std::string tx_blob = new_tx.serialize_tx();
                crypto::hash tx_hash_val;
                crypto::cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash_val);
                std::cout << "Transaction ID (hash): " << key_to_hex(tx_hash_val) << std::endl;
                
                for (const auto &vin_entry : new_tx.vin)
                {
                    db.put("key_images",
                           std::string(reinterpret_cast<const char *>(vin_entry.image.data), sizeof(crypto::key_image)),
                           std::string(reinterpret_cast<const char *>(tx_hash_val.data), sizeof(crypto::hash)));
                }
                std::cout << "Transaction ready. Key images for spent inputs have been recorded in the database." << std::endl;
            }
            else
            {
                std::cerr << "FAILURE: Transaction failed verification after construction." << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error during tx.make() or final verification: " << e.what() << std::endl;
            return 1;
        }
    }
}