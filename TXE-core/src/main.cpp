#include "wallet.cpp"
#include "tx.cpp"
#include "block.cpp"
#include "db.cpp"

#include <iostream>
#include <string>
#include <iomanip>
#include <cassert>
#include <vector>

#include <ringct/rctTypes.h>
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
    db.put("output_index", std::to_string(global_output_idx), ctkey_blob);

    // Update global count (simplified)
    uint64_t current_count = 0;
    try
    {
        current_count = db.count_fast("output_index");
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
    create_mock_spendable_output_for_wallet(db, 2, dummy_owner, 500, dummy_decoy_ctkey);
    create_mock_spendable_output_for_wallet(db, 3, dummy_owner, 800, dummy_decoy_ctkey);
    create_mock_spendable_output_for_wallet(db, 4, dummy_owner, 1200, dummy_decoy_ctkey);
    std::cout << "Created 3 additional outputs for potential decoys." << std::endl;

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
            2 /*mixin*/, hwdev);
        // Populate vout and ecdhInfo from signature
        for (size_t i = 0; i < correct_tx.vout.size(); ++i)
        {
            correct_tx.vout[i].ephemeral_pub_key = reinterpret_cast<const crypto::public_key &>(correct_tx.signature.outPk[i].dest);
            correct_tx.vout[i].commitment = correct_tx.signature.outPk[i].mask;
        }
        correct_tx.ecdh_info = correct_tx.signature.ecdhInfo;

        std::cout << "Correct TX created. Verifying..." << std::endl;
        bool verified_correct = correct_tx.ver(true, true);
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
        bool verified_tampered_bp = tampered_tx_bp.ver(true, true);
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
        bool verified_tampered_clsag_s = tampered_tx_clsag_s.ver(true, true);
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
    bool verified_tampered_fee = tampered_tx_fee.ver(true, true); // ver uses this tampered_tx_fee to recalc message
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
    bool verified_spent_ki = correct_tx.ver(true, true); // Semantic and sig checks should pass, but KI check should fail
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
    // Simplified main: just runs tests if no other command.
    // Or you can add a "test" command: if (std::string(argv[1]) == "test")
    if (argc == 2 && std::string(argv[1]) == "runtests")
    {
        std::string db_path = "./test_tx_db_data";
        std::filesystem::remove_all(db_path); // Clean previous test run
        TXE::SimpleLMDB db(db_path);
        hw::device &hwdev = hw::get_device("default");

        // Create necessary DBIs
        MDB_txn *setup_txn;
        mdb_txn_begin(db.env, nullptr, 0, &setup_txn);
        db.get_dbi("blocks", setup_txn);
        db.get_dbi("tips", setup_txn);
        db.get_dbi("key_images", setup_txn);
        db.get_dbi("transactions", setup_txn);
        db.get_dbi("output_index", setup_txn);
        db.get_dbi("outputs", setup_txn); // Ensure "outputs" is what populate_ring counts
        db.get_dbi("metadata", setup_txn);
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
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (std::string(argv[1]) == "init")
    {
        TXE::SimpleLMDB db("./lmdb_data");
        MDB_txn *txn;
        if (mdb_txn_begin(db.env, nullptr, 0, &txn))
            throw std::runtime_error("Failed to begin init transaction");

        db.get_dbi("blocks", txn);
        db.get_dbi("tips", txn);
        db.get_dbi("key_images", txn);
        db.get_dbi("transactions", txn);
        db.get_dbi("outputs", txn);
        db.get_dbi("output_indexes", txn);

        if (mdb_txn_commit(txn))
            throw std::runtime_error("Failed to commit init transaction");

        std::cout << "LMDB initialized with tables: blocks, key_images, ring_members, transactions, outputs" << std::endl;
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

            TXE::WalletKeys k;
            k.generate();
            k.save(std::string(argv[3]), pass);
            std::cout << "wallet keys saved at: " << std::string(argv[3]) << std::endl;
        }
    }
    return 0;
}