#ifndef TCRS_IMPL_H
#define TCRS_IMPL_H

#include "tcrs.h" // Your interface file
#include "tcrs_types.h"
#include "db.h"     // Your RocksDB wrapper
#include "sha512.h" // Your SHA512 wrapper
#include "util.h"   // Your util

#include <memory> // For std::unique_ptr
#include <iostream> // For debugging


bool TCRSImpl::relic_initialized_ = false;

tktktk
void TCRSImpl::initialize_relic_if_needed() {
    if (!relic_initialized_) {
        if (core_init() != RLC_OK) {
            throw std::runtime_error("RELIC core_init() failed");
        }
        // For Type 1 (symmetric) pairing, G1 = G2.
        // Using ep_param_set_mnt224().
        if (ep_param_set_mnt224() != RLC_OK) {
            core_clean();
            throw std::runtime_error("RELIC ep_param_set_mnt224() failed");
        }
        relic_initialized_ = true;
    }
}

void TCRSImpl::hash_string_to_bn(bn_t result_bn, const std::string& input_str, const bn_t order_q) {
    std::vector<unsigned char> input_vec(input_str.begin(), input_str.end());
    std::vector<unsigned char> hash_output = hash512(input_vec); // From your sha512.h
    bn_read_bin(result_bn, hash_output.data(), hash_output.size());
    bn_mod(result_bn, result_bn, order_q);
}


TCRSImpl::TCRSImpl(const std::string& trk_db_location, const std::string& user_db_location)
    : trk_loaded_(false), master_secret_loaded_(false) {
    initialize_relic_if_needed();
    bn_new(cached_master_secret_a_); // Initialize RELIC type

    try {
        trk_db_ = open_db(trk_db_location);         // From your db.h
        user_psk_db_ = open_db(user_db_location);   // From your db.h
    } catch (const std::exception& e) {
        // Clean up RELIC types if constructor fails partially
        bn_free(cached_master_secret_a_);
        std::cerr << "Failed to open databases: " << e.what() << std::endl;
        throw; // Re-throw
    }

    // Attempt to load existing parameters
    load_trk_from_db();
    load_master_secret_from_db();
}

TCRSImpl::~TCRSImpl() {
    bn_free(cached_master_secret_a_);
    // RocksDB unique_ptrs will auto-close.
    // RELIC core_clean() should be called globally once, not here unless this is the sole user.
}

bool TCRSImpl::load_trk_from_db() {
    std::string trk_str = db_get(trk_db_.get(), DB_KEY_TRK);
    if (!trk_str.empty()) {
        try {
            cached_trk_.deserialize(trk_str);
            trk_loaded_ = true;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Failed to deserialize TRK from DB: " << e.what() << std::endl;
            trk_loaded_ = false; // Mark as not loaded
        }
    }
    return false;
}

bool TCRSImpl::load_master_secret_from_db() {
    std::string secret_str = db_get(trk_db_.get(), DB_KEY_MASTER_SECRET_A);
    if (!secret_str.empty()) {
         try {
            string_to_bn_custom(cached_master_secret_a_, secret_str);
            master_secret_loaded_ = true;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Failed to deserialize master secret from DB: " << e.what() << std::endl;
            master_secret_loaded_ = false;
        }
    }
    return false;
}


bool TCRSImpl::system_setup(PublicParameters& trk_out, int /*security_parameter_k*/) {
    if (trk_loaded_ && master_secret_loaded_) {
        // std::cout << "System parameters already loaded from DB. Using existing." << std::endl;
        trk_out = cached_trk_; // Copy from cache
        return true;
    }
    // std::cout << "Generating new system parameters..." << std::endl;

    PublicParameters new_trk; // Temporary
    bn_t new_master_secret_a; bn_new(new_master_secret_a);

    pc_get_ord(new_trk.q); // Get group order q
    bn_rand_mod(new_master_secret_a, new_trk.q); // Generate master secret 'a' for TA
    g1_get_gen(new_trk.g); // Get generator g for G1
    g1_mul(new_trk.g1, new_trk.g, new_master_secret_a); // g1 = g^a

    // Randomly choose g2, vau, psi, dollar, mu, tau, chi, kappa from G1
    g1_rand(new_trk.g2); g1_rand(new_trk.vau); g1_rand(new_trk.psi);
    g1_rand(new_trk.dollar); g1_rand(new_trk.mu); g1_rand(new_trk.tau);
    g1_rand(new_trk.chi); g1_rand(new_trk.kappa);

    // Persist to DB
    try {
        db_add(trk_db_.get(), DB_KEY_TRK, new_trk.serialize());
        db_add(trk_db_.get(), DB_KEY_MASTER_SECRET_A, bn_to_string_custom(new_master_secret_a));
    } catch (const std::exception& e) {
        std::cerr << "DB error during system_setup: " << e.what() << std::endl;
        bn_free(new_master_secret_a);
        return false;
    }

    // Update cache and output
    cached_trk_ = new_trk;
    bn_copy(cached_master_secret_a_, new_master_secret_a);
    trk_loaded_ = true;
    master_secret_loaded_ = true;
    trk_out = cached_trk_;

    bn_free(new_master_secret_a);
    // std::cout << "New system parameters generated and saved." << std::endl;
    return true;
}

bool TCRSImpl::gen_key(const PublicParameters& trk, // trk is passed but we should use cached_trk_
                         PartialPrivateKey& psk_for_member_out,
                         UserSecretKey& sk_out,
                         UserPublicKey& pk_out) {
    if (!trk_loaded_ || !master_secret_loaded_) {
        std::cerr << "System parameters or master secret not loaded. Run system_setup or check DB." << std::endl;
        return false;
    }
    const PublicParameters& current_trk = cached_trk_; // Use cached TRK

    // --- TA Part ---
    bn_t r1; bn_new(r1);
    RLC_CHK(bn_rand_mod(r1, current_trk.q));

    g1_t g2_pow_a, dollar_pow_r1;
    g1_new(g2_pow_a); g1_new(dollar_pow_r1);

    g1_mul(g2_pow_a, current_trk.g2, cached_master_secret_a_);
    g1_mul(dollar_pow_r1, current_trk.dollar, r1);
    g1_add(psk_for_member_out.x0, g2_pow_a, dollar_pow_r1);
    g1_mul(psk_for_member_out.sL, current_trk.g, r1);

    g1_free(g2_pow_a); g1_free(dollar_pow_r1);

    // --- Member Part ---
    bn_t r2, H_pk_bn, exp_vau_bn;
    bn_new(r2); bn_new(H_pk_bn); bn_new(exp_vau_bn);

    RLC_CHK(bn_rand_mod(r2, current_trk.q));
    g1_mul(pk_out.key_val, current_trk.g, r2); // pk = g^r2

    hash_string_to_bn(H_pk_bn, pk_out.serialize(), current_trk.q); // H(pk)

    g1_t term_vau, term_psi;
    g1_new(term_vau); g1_new(term_psi);

    bn_mul(exp_vau_bn, r2, H_pk_bn);
    RLC_CHK(bn_mod(exp_vau_bn, exp_vau_bn, current_trk.q));
    g1_mul(term_vau, current_trk.vau, exp_vau_bn);
    g1_mul(term_psi, current_trk.psi, r2);

    g1_add(sk_out.x1, psk_for_member_out.x0, term_vau);
    g1_add(sk_out.x1, sk_out.x1, term_psi);
    g1_copy(sk_out.sL, psk_for_member_out.sL);

    g1_free(term_vau); g1_free(term_psi);
    bn_free(r1); bn_free(r2); bn_free(H_pk_bn); bn_free(exp_vau_bn);

    // Store PartialPrivateKey (psk_for_member_out) in user_psk_db_
    // Key: pk_out.serialize(), Value: psk_for_member_out.serialize()
    try {
        db_add(user_psk_db_.get(), pk_out.serialize(), psk_for_member_out.serialize());
    } catch (const std::exception& e) {
        std::cerr << "DB error during gen_key (storing PSK): " << e.what() << std::endl;
        return false; // Keygen succeeded cryptographically but DB failed.
    }
    return true;
}


bool TCRSImpl::sign(const PublicParameters& /*trk_param*/, // Use cached_trk_
                      const UserSecretKey& sk_signer,
                      const UserPublicKey& pk_signer,
                      const std::vector<UserPublicKey>& rl_pk_list,
                      const std::string& message,
                      const std::string& event_id,
                      Signature& sig_out) {
    if (!trk_loaded_) {
        std::cerr << "TRK not loaded for sign operation." << std::endl;
        return false;
    }
    const PublicParameters& trk = cached_trk_; // Use cached

    bn_t H_pk_bn, H_RL_PK_bn, H_MkE_bn, r3, r4, r5, exp_temp_bn;
    bn_new(H_pk_bn); bn_new(H_RL_PK_bn); bn_new(H_MkE_bn);
    bn_new(r3); bn_new(r4); bn_new(r5); bn_new(exp_temp_bn);

    hash_string_to_bn(H_pk_bn, pk_signer.serialize(), trk.q);

    std::string rl_pk_serialized_str;
    for (const auto& key : rl_pk_list) { rl_pk_serialized_str += key.serialize(); }
    hash_string_to_bn(H_RL_PK_bn, rl_pk_serialized_str, trk.q);

    hash_string_to_bn(H_MkE_bn, message + event_id, trk.q);

    RLC_CHK(bn_rand_mod(r3, trk.q));
    RLC_CHK(bn_rand_mod(r4, trk.q));
    RLC_CHK(bn_rand_mod(r5, trk.q));

    g1_t term_vau_pk, term_psi_r3, term_dollar_r3, term_mu_rlpk, term_tau_r4, term_chi_mke, term_kappa_r5;
    g1_new(term_vau_pk); g1_new(term_psi_r3); g1_new(term_dollar_r3);
    g1_new(term_mu_rlpk); g1_new(term_tau_r4); g1_new(term_chi_mke); g1_new(term_kappa_r5);

    bn_mul(exp_temp_bn, r3, H_pk_bn); RLC_CHK(bn_mod(exp_temp_bn, exp_temp_bn, trk.q));
    g1_mul(term_vau_pk, trk.vau, exp_temp_bn);
    g1_mul(term_psi_r3, trk.psi, r3);
    g1_mul(term_dollar_r3, trk.dollar, r3);
    bn_mul(exp_temp_bn, r4, H_RL_PK_bn); RLC_CHK(bn_mod(exp_temp_bn, exp_temp_bn, trk.q));
    g1_mul(term_mu_rlpk, trk.mu, exp_temp_bn);
    g1_mul(term_tau_r4, trk.tau, r4);
    bn_mul(exp_temp_bn, r5, H_MkE_bn); RLC_CHK(bn_mod(exp_temp_bn, exp_temp_bn, trk.q));
    g1_mul(term_chi_mke, trk.chi, exp_temp_bn);
    g1_mul(term_kappa_r5, trk.kappa, r5);

    g1_copy(sig_out.sigma0, sk_signer.x1);
    g1_add(sig_out.sigma0, sig_out.sigma0, term_vau_pk);
    g1_add(sig_out.sigma0, sig_out.sigma0, term_psi_r3);
    g1_add(sig_out.sigma0, sig_out.sigma0, term_dollar_r3);
    g1_add(sig_out.sigma0, sig_out.sigma0, term_mu_rlpk);
    g1_add(sig_out.sigma0, sig_out.sigma0, term_tau_r4);
    g1_add(sig_out.sigma0, sig_out.sigma0, term_chi_mke);
    g1_add(sig_out.sigma0, sig_out.sigma0, term_kappa_r5);

    g1_t base1_pair1, base1_pair2, g_pow_r3;
    gt_t pair1_val, pair2_val;
    g1_new(base1_pair1); g1_new(base1_pair2); g1_new(g_pow_r3);
    gt_new(pair1_val); gt_new(pair2_val);

    g1_mul(base1_pair1, trk.vau, H_pk_bn);
    g1_add(base1_pair1, base1_pair1, trk.psi);
    RLC_CHK(pc_map(pair1_val, base1_pair1, pk_signer.key_val));

    g1_add(base1_pair2, term_vau_pk, term_psi_r3);
    RLC_CHK(pc_map(pair2_val, base1_pair2, trk.g));
    gt_mul(sig_out.sigma1, pair1_val, pair2_val);

    g1_mul(g_pow_r3, trk.g, r3);
    g1_add(sig_out.sigma2, sk_signer.sL, g_pow_r3);
    g1_mul(sig_out.sigma3, trk.g, r4);
    g1_mul(sig_out.sigma4, trk.g, r5);

    // Free temporaries
    bn_free(H_pk_bn); bn_free(H_RL_PK_bn); bn_free(H_MkE_bn); bn_free(r3); bn_free(r4); bn_free(r5); bn_free(exp_temp_bn);
    g1_free(term_vau_pk); g1_free(term_psi_r3); g1_free(term_dollar_r3); g1_free(term_mu_rlpk);
    g1_free(term_tau_r4); g1_free(term_chi_mke); g1_free(term_kappa_r5);
    g1_free(base1_pair1); g1_free(base1_pair2); g1_free(g_pow_r3);
    gt_free(pair1_val); gt_free(pair2_val);
    return true;
}


bool TCRSImpl::verify(const PublicParameters& /*trk_param*/, // Use cached_trk_
                        const std::vector<UserPublicKey>& rl_pk_list,
                        const std::string& message,
                        const std::string& event_id,
                        const Signature& sig) {
    if (!trk_loaded_) {
        std::cerr << "TRK not loaded for verify operation." << std::endl;
        return false;
    }
    const PublicParameters& trk = cached_trk_; // Use cached

    gt_t lhs, term_g1g2, term_dollar_s2, term_mu_tau_s3, term_chi_kappa_s4, rhs;
    gt_new(lhs); gt_new(term_g1g2); gt_new(term_dollar_s2);
    gt_new(term_mu_tau_s3); gt_new(term_chi_kappa_s4); gt_new(rhs);

    RLC_CHK(pc_map(lhs, sig.sigma0, trk.g));
    RLC_CHK(pc_map(term_g1g2, trk.g1, trk.g2));
    RLC_CHK(pc_map(term_dollar_s2, trk.dollar, sig.sigma2));

    bn_t H_RL_PK_bn, H_MkE_bn;
    bn_new(H_RL_PK_bn); bn_new(H_MkE_bn);
    std::string rl_pk_s; for(const auto& k : rl_pk_list) rl_pk_s += k.serialize();
    hash_string_to_bn(H_RL_PK_bn, rl_pk_s, trk.q);
    hash_string_to_bn(H_MkE_bn, message + event_id, trk.q);

    g1_t base_mu_tau_g1, base_chi_kappa_g1;
    g1_new(base_mu_tau_g1); g1_new(base_chi_kappa_g1);
    g1_mul(base_mu_tau_g1, trk.mu, H_RL_PK_bn); g1_add(base_mu_tau_g1, base_mu_tau_g1, trk.tau);
    RLC_CHK(pc_map(term_mu_tau_s3, base_mu_tau_g1, sig.sigma3));
    g1_mul(base_chi_kappa_g1, trk.chi, H_MkE_bn); g1_add(base_chi_kappa_g1, base_chi_kappa_g1, trk.kappa);
    RLC_CHK(pc_map(term_chi_kappa_s4, base_chi_kappa_g1, sig.sigma4));

    gt_mul(rhs, term_g1g2, sig.sigma1); gt_mul(rhs, rhs, term_dollar_s2);
    gt_mul(rhs, rhs, term_mu_tau_s3); gt_mul(rhs, rhs, term_chi_kappa_s4);

    bool result = (gt_cmp(lhs, rhs) == RLC_EQ);

    gt_free(lhs); gt_free(term_g1g2); gt_free(term_dollar_s2); gt_free(term_mu_tau_s3); gt_free(term_chi_kappa_s4); gt_free(rhs);
    bn_free(H_RL_PK_bn); bn_free(H_MkE_bn);
    g1_free(base_mu_tau_g1); g1_free(base_chi_kappa_g1);
    return result;
}


std::string TCRSImpl::trace_user(const PublicParameters& /*trk_param*/, // Use cached_trk_
                                   const std::vector<UserPublicKey>& rl_pk_list,
                                   const std::string& m1_str, const Signature& sig1,
                                   const std::string& m2_str, const Signature& sig2,
                                   const std::string& event_id_str,
                                   const std::map<std::string, PartialPrivateKey>& psk_db) {
    if (!trk_loaded_) {
        std::cerr << "TRK not loaded for trace_user operation." << std::endl;
        return "Error: TRK not loaded";
    }
    const PublicParameters& trk = cached_trk_; // Use cached

    UserPublicKey pk_of_signer1, pk_of_signer2;
    bool found1 = false, found2 = false;

    auto find_one_signer_lambda =
        [&](const std::string& msg_str, const Signature& current_sig, UserPublicKey& pk_found_out) -> bool {
        bn_t H_MkE_bn, H_RL_PK_bn;
        bn_new(H_MkE_bn); bn_new(H_RL_PK_bn);
        hash_string_to_bn(H_MkE_bn, msg_str + event_id_str, trk.q);
        std::string rl_s; for(const auto& k : rl_pk_list) rl_s += k.serialize();
        hash_string_to_bn(H_RL_PK_bn, rl_s, trk.q);

        gt_t e_s0_g, e_g1_g2, e_dollar_s2, e_mu_tau_s3, e_chi_kappa_s4, rhs_trace_target, denom_trace, inv_denom_trace;
        gt_new(e_s0_g); gt_new(e_g1_g2); gt_new(e_dollar_s2); gt_new(e_mu_tau_s3); gt_new(e_chi_kappa_s4);
        gt_new(rhs_trace_target); gt_new(denom_trace); gt_new(inv_denom_trace);
        g1_t base_mu_tau_g1, base_chi_kappa_g1;
        g1_new(base_mu_tau_g1); g1_new(base_chi_kappa_g1);

        RLC_CHK(pc_map(e_s0_g, current_sig.sigma0, trk.g));
        RLC_CHK(pc_map(e_g1_g2, trk.g1, trk.g2));
        RLC_CHK(pc_map(e_dollar_s2, trk.dollar, current_sig.sigma2));
        g1_mul(base_mu_tau_g1, trk.mu, H_RL_PK_bn); g1_add(base_mu_tau_g1, base_mu_tau_g1, trk.tau);
        RLC_CHK(pc_map(e_mu_tau_s3, base_mu_tau_g1, current_sig.sigma3));
        g1_mul(base_chi_kappa_g1, trk.chi, H_MkE_bn); g1_add(base_chi_kappa_g1, base_chi_kappa_g1, trk.kappa);
        RLC_CHK(pc_map(e_chi_kappa_s4, base_chi_kappa_g1, current_sig.sigma4));

        gt_mul(denom_trace, e_g1_g2, e_dollar_s2); gt_mul(denom_trace, denom_trace, e_mu_tau_s3);
        gt_mul(denom_trace, denom_trace, e_chi_kappa_s4);
        gt_inv(inv_denom_trace, denom_trace);
        gt_mul(rhs_trace_target, e_s0_g, inv_denom_trace);

        bool current_found = false;
        for (const auto& pk_cand : rl_pk_list) {
            auto it_psk = psk_db.find(pk_cand.serialize());
            if (it_psk == psk_db.end()) continue;
            const PartialPrivateKey& psk_candidate = it_psk->second;

            bn_t H_pk_cand_bn; bn_new(H_pk_cand_bn);
            hash_string_to_bn(H_pk_cand_bn, pk_cand.serialize(), trk.q);

            g1_t A_g1, B_g1, g_r3_cand_g1, sL_cand_inv_g1; gt_t lhs_cand_gt;
            g1_new(A_g1); g1_new(B_g1); g1_new(g_r3_cand_g1); g1_new(sL_cand_inv_g1); gt_new(lhs_cand_gt);

            g1_mul(A_g1, trk.vau, H_pk_cand_bn); g1_add(A_g1, A_g1, trk.psi);
            g1_neg(sL_cand_inv_g1, psk_candidate.sL);
            g1_add(g_r3_cand_g1, current_sig.sigma2, sL_cand_inv_g1);
            g1_add(B_g1, pk_cand.key_val, g_r3_cand_g1);
            RLC_CHK(pc_map(lhs_cand_gt, A_g1, B_g1));

            if (gt_cmp(lhs_cand_gt, rhs_trace_target) == RLC_EQ) {
                pk_found_out = pk_cand; current_found = true;
                bn_free(H_pk_cand_bn); g1_free(A_g1); g1_free(B_g1); g1_free(g_r3_cand_g1); g1_free(sL_cand_inv_g1); gt_free(lhs_cand_gt);
                break;
            }
            bn_free(H_pk_cand_bn); g1_free(A_g1); g1_free(B_g1); g1_free(g_r3_cand_g1); g1_free(sL_cand_inv_g1); gt_free(lhs_cand_gt);
        }
        bn_free(H_MkE_bn); bn_free(H_RL_PK_bn);
        gt_free(e_s0_g); gt_free(e_g1_g2); gt_free(e_dollar_s2); gt_free(e_mu_tau_s3); gt_free(e_chi_kappa_s4);
        gt_free(rhs_trace_target); gt_free(denom_trace); gt_free(inv_denom_trace);
        g1_free(base_mu_tau_g1); g1_free(base_chi_kappa_g1);
        return current_found;
    };

    found1 = find_one_signer_lambda(m1_str, sig1, pk_of_signer1);
    found2 = find_one_signer_lambda(m2_str, sig2, pk_of_signer2);

    if (!found1 && !found2) return "Error: Signer for S1 not found AND Signer for S2 not found";
    if (!found1) return "Error: Signer for S1 not found";
    if (!found2) return "Error: Signer for S2 not found";

    if (!(pk_of_signer1 == pk_of_signer2)) return "Independent";
    return (m1_str == m2_str) ? "Linked" : ("pk:" + pk_of_signer1.serialize());
}

// Implementation for load_user_psk
bool TCRSImpl::load_user_psk(const UserPublicKey& pk, PartialPrivateKey& psk_out) {
    std::string psk_str = db_get(user_psk_db_.get(), pk.serialize());
    if (!psk_str.empty()) {
        try {
            psk_out.deserialize(psk_str);
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Failed to deserialize PSK for PK " << pk.serialize() << " from DB: " << e.what() << std::endl;
        }
    }
    return false;
}

#endif // TCRS_IMPL_H