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

template <typename T>
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
    const unsigned char *key_data = reinterpret_cast<const unsigned char *>(key_obj.bytes);
    for (size_t i = 0; i < sizeof(key_obj.bytes); ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_data[i]);
    }
    return ss.str();
}

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

std::pair<rct::key, rct::key> create_mock_spendable_output_for_wallet(
    TXE::SimpleLMDB &db,
    size_t global_output_idx,
    const TXE::WalletKeys &recipient_wallet,
    uint64_t amount,
    rct::ctkey &generated_ctkey
)
{
    crypto::secret_key tx_ephemeral_sk_r;
    crypto::public_key tx_ephemeral_pk_R;
    crypto::generate_keys(tx_ephemeral_pk_R, tx_ephemeral_sk_r);

    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(recipient_wallet.spend_pub, tx_ephemeral_sk_r, derivation))
    {
        throw std::runtime_error("Test setup: Failed to generate derivation for mock output");
    }

    crypto::public_key one_time_output_pk_P;
    if (!crypto::derive_public_key(derivation, 0 /*output index in this fake tx*/, recipient_wallet.spend_pub, one_time_output_pk_P))
    {
        throw std::runtime_error("Test setup: Failed to derive public key for mock output");
    }
    generated_ctkey.dest = rct::pk2rct(one_time_output_pk_P);

    crypto::secret_key one_time_output_sk_x;
    crypto::derive_secret_key(derivation, 0, recipient_wallet.spend_sec, one_time_output_sk_x);

    rct::key commitment_mask_a = rct::skGen();
    generated_ctkey.mask = rct::commit(amount, commitment_mask_a);

    std::string ctkey_blob;
    ctkey_blob.append(reinterpret_cast<const char *>(generated_ctkey.mask.bytes), 32);
    ctkey_blob.append(reinterpret_cast<const char *>(generated_ctkey.dest.bytes), 32);
    db.put("output_indexes", std::to_string(global_output_idx), ctkey_blob);
    db.put("outputs", std::to_string(global_output_idx), "TEST");

    uint64_t current_count = 0;
    try
    {
        current_count = db.count_fast("output_indexes");
    }
    catch (...)
    { /*ignore if table empty*/
    }
    return {rct::sk2rct(one_time_output_sk_x), commitment_mask_a};
}

void test_transactions(TXE::SimpleLMDB &db, hw::device &hwdev)
{
    std::cout << "\n--- Starting Transaction Tests ---" << std::endl;


    TXE::WalletKeys sender_wallet = TXE::WalletKeys::generate();
    TXE::WalletKeys recipient_wallet = TXE::WalletKeys::generate();
    std::cout << "Sender Spend Pub: " << key_to_hex(sender_wallet.spend_pub) << std::endl;
    std::cout << "Recipient Spend Pub: " << key_to_hex(recipient_wallet.spend_pub) << std::endl;

    uint64_t input1_amount = 10000;
    rct::ctkey input1_pk_on_chain;
    auto [input1_sk_x, input1_mask_a] = create_mock_spendable_output_for_wallet(
        db, 0, sender_wallet, input1_amount, input1_pk_on_chain);
    std::cout << "Created mock spendable input 0 (global_idx 0) for sender with amount " << input1_amount << std::endl;

    uint64_t input2_amount = 7000;
    rct::ctkey input2_pk_on_chain;
    auto [input2_sk_x, input2_mask_a] = create_mock_spendable_output_for_wallet(
        db, 1, sender_wallet, input2_amount, input2_pk_on_chain);
    std::cout << "Created mock spendable input 1 (global_idx 1) for sender with amount " << input2_amount << std::endl;

    rct::ctkey dummy_decoy_ctkey;
    TXE::WalletKeys dummy_owner = TXE::WalletKeys::generate();
    std::cout << "Creating decoy outputs..." << std::endl;
    for (int i = 2; i < 17; i++)
    {
        create_mock_spendable_output_for_wallet(db, i, dummy_owner, 500 + (i * 100), dummy_decoy_ctkey);
    }
    std::cout << "Created 15 additional outputs for decoys " << std::endl;

    std::cout << "\n--- Test 1: Correct Transaction ---" << std::endl;
    TXE::tx correct_tx;
    correct_tx.version = 1;
    correct_tx.signature.type = rct::RCTTypeCLSAG;

    std::vector<rct::ctkey> correct_in_sk_vec;
    std::vector<rct::ctkey> correct_in_pk_vec;
    std::vector<uint64_t> correct_in_amounts_vec;

    TXE::tx_input tx_in1_struct;
    tx_in1_struct.amount = input1_amount;
    crypto::generate_key_image(reinterpret_cast<const crypto::public_key &>(input1_pk_on_chain.dest),
                               reinterpret_cast<const crypto::secret_key &>(input1_sk_x),
                               tx_in1_struct.image);
    tx_in1_struct.key_offsets = {0};
    correct_tx.vin.push_back(tx_in1_struct);

    correct_in_sk_vec.push_back({input1_sk_x, input1_mask_a});
    correct_in_pk_vec.push_back(input1_pk_on_chain);
    correct_in_amounts_vec.push_back(input1_amount);

    uint64_t amount_to_recipient = 6000;
    uint64_t fee = 500;
    uint64_t change_to_sender = input1_amount - amount_to_recipient - fee;

    std::vector<std::pair<crypto::public_key, uint64_t>> conceptual_outputs;
    conceptual_outputs.push_back({recipient_wallet.spend_pub, amount_to_recipient});
    if (change_to_sender > 0)
    {
        conceptual_outputs.push_back({sender_wallet.spend_pub, change_to_sender});
    }
    correct_tx.vout.resize(conceptual_outputs.size());

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

        db.put("key_images", std::string(reinterpret_cast<const char *>(correct_tx.vin[0].image.data), 32), "spent_in_test1");
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error in Correct Transaction Test: " << e.what() << std::endl;
        assert(false && "Correct transaction test threw exception.");
    }

    std::cout << "\n--- Test 2: Malformed Transaction (Tampered Bulletproof.A) ---" << std::endl;
    if (!correct_tx.signature.p.bulletproofs.empty())
    {
        TXE::tx tampered_tx_bp = correct_tx;
        if (!(tampered_tx_bp.signature.p.bulletproofs[0].A == rct::zero()))
        {
            tampered_tx_bp.signature.p.bulletproofs[0].A.bytes[0] ^= 0xFF;
        }
        else
        {
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

    std::cout << "\n--- Test 3: Malformed Transaction (Tampered CLSAG.s) ---" << std::endl;
    if (!correct_tx.signature.p.CLSAGs.empty() && !correct_tx.signature.p.CLSAGs[0].s.empty())
    {
        TXE::tx tampered_tx_clsag_s = correct_tx;
        tampered_tx_clsag_s.signature.p.CLSAGs[0].s[0].bytes[0] ^= 0xFF;

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

    std::cout << "\n--- Test 4: Malformed Transaction (Tampered Tx Fee -> Message Mismatch) ---" << std::endl;
    TXE::tx tampered_tx_fee = correct_tx;
    tampered_tx_fee.fee += 100;

    std::cout << "Tampered tx.fee (message for CLSAG will mismatch). Verifying..." << std::endl;
    bool verified_tampered_fee = tampered_tx_fee.ver(db, true, true, true);
    assert(!verified_tampered_fee && "Transaction with tampered fee unexpectedly VERIFIED!");
    if (!verified_tampered_fee)
    {
        std::cout << "SUCCESS: Transaction with tampered fee correctly FAILED verification." << std::endl;
    }

    std::cout << "\n--- Test 5: Malformed Transaction (Spent Key Image) ---" << std::endl;
    std::cout << "Attempting to verify transaction with already spent key image..." << std::endl;
    bool verified_spent_ki = correct_tx.ver(db, true, true, true);
    assert(!verified_spent_ki && "Transaction with spent key image unexpectedly VERIFIED (or an earlier check failed this path)!");
    if (!verified_spent_ki)
    {
        std::cout << "SUCCESS: Transaction with spent key image correctly FAILED verification." << std::endl;
    }


    std::cout << "\n--- Transaction Tests Finished ---" << std::endl;
}

int test(int argc, char *argv[])
{
    std::string db_path = "./lmdb_data";
    std::filesystem::remove_all(db_path);
    TXE::SimpleLMDB db(db_path);
    hw::device &hwdev = hw::get_device("default");

    MDB_txn *setup_txn;
    mdb_txn_begin(db.env, nullptr, 0, &setup_txn);
    db.get_dbi("blocks", setup_txn);
    db.get_dbi("tips", setup_txn);
    db.get_dbi("key_images", setup_txn);
    db.get_dbi("transactions", setup_txn);
    db.get_dbi("outputs", setup_txn);
    db.get_dbi("output_indexes", setup_txn);
    db.get_dbi("mempool", setup_txn);
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
    TXE::SimpleLMDB &db,
    hw::device &hwdev,
    const crypto::secret_key &genesis_master_secret_key
)
{
    std::cout << "Creating deterministic genesis block..." << std::endl;

    const uint64_t GENESIS_TIMESTAMP = 1748810142;
    const std::string GENESIS_EXTRA_MESSAGE = "Genesis 1: 26-28";
    const uint64_t GENESIS_COINBASE_AMOUNT = 10000000;
    const uint32_t GENESIS_TX_VERSION = 1;
    const uint32_t GENESIS_BLOCK_VERSION = 1;
    const uint64_t GENESIS_NONCE = 0;
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


    crypto::secret_key genesis_recipient_spend_sk_derived;
    crypto::public_key genesis_recipient_spend_pk_derived;
    crypto::hash recipient_sk_hash;
    crypto::cn_fast_hash(&genesis_master_secret_key, sizeof(genesis_master_secret_key), recipient_sk_hash);
    genesis_recipient_spend_sk_derived = reinterpret_cast<const crypto::secret_key &>(recipient_sk_hash);
    crypto::secret_key_to_public_key(genesis_recipient_spend_sk_derived, genesis_recipient_spend_pk_derived);
    crypto::hash view_key_seed_hash;
    crypto::cn_fast_hash(&genesis_master_secret_key, sizeof(genesis_master_secret_key), view_key_seed_hash);
    crypto::secret_key genesis_recipient_view_sk_derived = reinterpret_cast<const crypto::secret_key &>(view_key_seed_hash);
    crypto::public_key genesis_recipient_view_pk_derived;
    crypto::secret_key_to_public_key(genesis_recipient_view_sk_derived, genesis_recipient_view_pk_derived);

    crypto::hash dummy_input_sk_seed_hash;
    char dummy_seed_modifier[] = "dummy_input";
    std::string dummy_input_seed_material = std::string(reinterpret_cast<const char *>(genesis_master_secret_key.data), sizeof(genesis_master_secret_key.data)) + dummy_seed_modifier;
    crypto::cn_fast_hash(dummy_input_seed_material.data(), dummy_input_seed_material.size(), dummy_input_sk_seed_hash);

    rct::ctkey genesis_dummy_inSk;
    genesis_dummy_inSk.dest = rct::sk2rct(reinterpret_cast<const crypto::secret_key &>(dummy_input_sk_seed_hash));
    rct::skpkGen(genesis_dummy_inSk.dest, genesis_dummy_inSk.mask);
    rct::ctkey genesis_dummy_inPk;
    genesis_dummy_inPk.dest = genesis_dummy_inSk.mask;
    genesis_dummy_inPk.mask = rct::identity();

    char header_seed_modifier[] = "The name of God is sacred";
    crypto::hash genesis_header_randomx_seed = crypto::cn_fast_hash(header_seed_modifier, 26);

    TXE::tx coinbase_tx;
    coinbase_tx.version = GENESIS_TX_VERSION;
    coinbase_tx.fee = 0;
    coinbase_tx.signature.type = rct::RCTTypeCLSAG;

    TXE::tx_input dummy_input;
    dummy_input.amount = 0;
    crypto::generate_key_image(reinterpret_cast<const crypto::public_key &>(genesis_dummy_inPk.dest),
                               reinterpret_cast<const crypto::secret_key &>(genesis_dummy_inSk.dest),
                               dummy_input.image);
    dummy_input.key_offsets = {};
    coinbase_tx.vin.push_back(dummy_input);

    coinbase_tx.vout.resize(1);

    coinbase_tx.extra.assign(GENESIS_EXTRA_MESSAGE.begin(), GENESIS_EXTRA_MESSAGE.end());

    std::vector<rct::ctkey> in_sk_vec = {genesis_dummy_inSk};
    std::vector<rct::ctkey> in_pk_vec = {genesis_dummy_inPk};
    std::vector<uint64_t> in_amounts_vec = {0};

    crypto::secret_key tx_ephemeral_sk_r_genesis;
    crypto::public_key tx_ephemeral_pk_R_genesis;
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

    std::cout << "   Making genesis coinbase signature..." << std::endl;
    coinbase_tx.signature = coinbase_tx.make(
        in_sk_vec, in_pk_vec, destinations_for_make,
        in_amounts_vec, out_amounts_for_make, amount_keys_for_make,
        0 /*mixin for genesis coinbase input*/, hwdev, db);

    if (coinbase_tx.signature.outPk.size() != 1 || coinbase_tx.signature.ecdhInfo.size() != 1)
    {
        throw std::runtime_error("Genesis coinbase creation: outPk or ecdhInfo not correctly sized by genRctSimple.");
    }
    coinbase_tx.vout[0].ephemeral_pub_key = reinterpret_cast<const crypto::public_key &>(coinbase_tx.signature.outPk[0].dest);
    coinbase_tx.vout[0].commitment = coinbase_tx.signature.outPk[0].mask;
    coinbase_tx.ecdh_info = coinbase_tx.signature.ecdhInfo;

    std::cout << "   Genesis coinbase transaction created." << std::endl;

    TXE::header genesis_header;
    genesis_header.ver = GENESIS_BLOCK_VERSION;
    genesis_header.timestamp = GENESIS_TIMESTAMP;
    genesis_header.nonce = GENESIS_NONCE;
    genesis_header.target = GENESIS_TARGET;
    genesis_header.tip_ids.clear();

    std::string miner_tx_blob = coinbase_tx.serialize_tx();
    crypto::cn_fast_hash(miner_tx_blob.data(), miner_tx_blob.size(), genesis_header.merkle_root);

    genesis_header.seed = genesis_header_randomx_seed;

    std::cout << "   Calculating genesis block header ID..." << std::endl;
    genesis_header.calculate_header_id(genesis_header.header_id, GENESIS_TARGET);
    std::cout << "   Genesis block header ID calculated." << std::endl;

    TXE::block genesis_block_obj;
    genesis_block_obj.hdr = genesis_header;
    genesis_block_obj.miner_tx = coinbase_tx;
    genesis_block_obj.txlist.clear();

    std::cout << "Genesis block assembled." << std::endl;

    return genesis_block_obj;
}

bool print_all_dbis(MDB_env *env) {
    if (!env) {
        std::cerr << "Error: Provided MDB_env is null." << std::endl;
        return false;
    }

    MDB_txn *txn = nullptr;
    MDB_dbi main_dbi;
    MDB_cursor *cursor = nullptr;

    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) {
        std::cerr << "Error beginning read-only transaction: " << mdb_strerror(rc) << std::endl;
        return false;
    }

    rc = mdb_dbi_open(txn, nullptr, 0, &main_dbi);
    if (rc != 0) {
        std::cerr << "Error opening main DBI: " << mdb_strerror(rc) << std::endl;
        mdb_txn_abort(txn);
        return false;
    }

    rc = mdb_cursor_open(txn, main_dbi, &cursor);
    if (rc != 0) {
        std::cerr << "Error opening cursor on main DBI: " << mdb_strerror(rc) << std::endl;
        mdb_txn_abort(txn);
        return false;
    }

    std::cout << "Named DBIs found in the environment:" << std::endl;
    MDB_val key, data;
    size_t count = 0;

    while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        std::string dbi_name(static_cast<char*>(key.mv_data), key.mv_size);
        std::cout << "  - " << dbi_name << std::endl;
        count++;
    }

    if (rc != MDB_NOTFOUND) {
        std::cerr << "Error during cursor iteration: " << mdb_strerror(rc) << std::endl;
    }
    
    if (count == 0) {
        std::cout << "  (No named sub-databases found)" << std::endl;
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    return true;
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
        std::filesystem::remove_all("./lmdb_data");
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
        db.get_dbi("mempool", txn);

        if (mdb_txn_commit(txn))
            throw std::runtime_error("Failed to commit init transaction");

        print_all_dbis(db.env);

        std::cout << "LMDB initialized with tables: blocks, key_images, ring_members, transactions, outputs" << std::endl;

        crypto::secret_key genesis_key;
        std::string seed_string = "One Way!";
        crypto::hash seed_hash;
        crypto::cn_fast_hash(seed_string.data(), seed_string.length(), seed_hash);
        std::memcpy(genesis_key.data, seed_hash.data, sizeof(genesis_key.data));
        TXE::block genesis = create_deterministic_genesis_block(db, hw::get_device("default"), genesis_key);
        TXE::block::add_block_to_db(genesis, &db);
        mdb_env_sync(db.env, 1);
    }
    if (std::string(argv[1]) == "wallet")
    {
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
        std::cin >> password;

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

        print_all_dbis(db.env);

MDB_txn *wallet_scan_txn = nullptr;
MDB_dbi dbi_blocks_main = 0;
MDB_dbi dbi_key_images_main = 0;
std::vector<TXE::SpendableOutputInfo> owned_outputs;

try {
    if (mdb_txn_begin(db.env, nullptr, MDB_RDONLY, &wallet_scan_txn)) {
        throw std::runtime_error("Failed to begin transaction for wallet scan.");
    }
    dbi_blocks_main = db.open_existing_dbi("blocks", wallet_scan_txn);
    dbi_key_images_main = db.open_existing_dbi("key_images", wallet_scan_txn);

    std::cout << "Scanning blockchain for spendable outputs (external transaction)..." << std::endl;
    owned_outputs = sender_wallet.get_owned(wallet_scan_txn, dbi_blocks_main, dbi_key_images_main);
    
    mdb_txn_abort(wallet_scan_txn);
    wallet_scan_txn = nullptr;
    std::cout << "Wallet sync complete." << std::endl;

} catch (const std::exception& e) {
    if (wallet_scan_txn) {
        mdb_txn_abort(wallet_scan_txn);
    }
    std::cerr << "Error during wallet sync or DB setup: " << e.what() << std::endl;
    return 1;
}

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
            std::cout << "  - Amount: " << out.amount
                      << ", Global Index (approx if from block scan): " << out.global_index 
                      << ", P: " << key_to_hex(out.pk_on_chain.dest).substr(0, 10) << "..." << std::endl;
        }
        std::cout << "Total available balance: " << total_owned_balance << std::endl;

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
        if (fee == 0)
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

        std::sort(owned_outputs.begin(), owned_outputs.end(),
                  [](const TXE::SpendableOutputInfo &a, const TXE::SpendableOutputInfo &b)
                  {
                      return a.amount > b.amount;
                  });

        std::vector<TXE::SpendableOutputInfo> selected_inputs_info;
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
                break;
            }
        }

        if (current_input_sum < total_required_for_tx)
        {
            std::cerr << "Error: Failed to select sufficient inputs even after initial balance check. (Available sum: " << current_input_sum << ")" << std::endl;
            return 1;
        }
        std::cout << "Selected " << selected_inputs_info.size() << " inputs with a total value of " << current_input_sum << std::endl;

        uint64_t change_amount = current_input_sum - total_required_for_tx;
        if (change_amount > 0)
        {
            std::cout << "Change to be returned to sender: " << change_amount << std::endl;
            conceptual_dests_amounts.push_back({sender_wallet.spend_pub, change_amount});
        }

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
            num_decoys_available_on_chain = db.count_fast("output_indexes");
        }
        catch (...) { /* ignore if table empty or error */ }

        int mixin_count = 3;
        if (num_decoys_available_on_chain <= 1) 
        { 
            mixin_count = 0;
            if (num_decoys_available_on_chain > 0) {
                 std::cout << "Warning: Not enough distinct outputs on chain for decoys (or 'output_indexes' table is too small). Mixin set to 0." << std::endl;
            } else {
                 std::cout << "Info: No outputs found in 'output_indexes' table. Mixin set to 0." << std::endl;
            }
        }
        else if (num_decoys_available_on_chain - 1 < static_cast<size_t>(mixin_count))
        {
            mixin_count = num_decoys_available_on_chain - 1;
            std::cout << "Warning: Adjusting mixin to " << mixin_count 
                      << " due to limited number of decoy candidates in 'output_indexes' table." << std::endl;
        }
        std::cout << "Using mixin count: " << mixin_count << " (ring size " << mixin_count + 1 << ")" << std::endl;

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
