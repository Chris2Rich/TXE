#ifndef __tx
#define __tx

#include "db.cpp"
#include <crypto/crypto.h>
#include <ringct/rctOps.h>
#include <ringct/rctTypes.h>
#include <ringct/rctSigs.h>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <functional>
#include <tuple>

namespace TXE
{

  struct tx_input
  {
    uint64_t amount;
    crypto::key_image image;
    std::vector<uint64_t> key_offsets;

    tx_input() : amount(0) {}
    tx_input(const crypto::key_image &img, const std::vector<uint64_t> &offsets, uint64_t amt = 0)
        : amount(amt), image(img), key_offsets(offsets) {}
  };

  struct tx_output
  {
    crypto::public_key ephemeral_pub_key;
    rct::key commitment;
    std::string opcodes;

    tx_output() = default;
    tx_output(const crypto::public_key &pk,
              const rct::key &comm,
              const std::string &opc = "")
        : ephemeral_pub_key(pk), commitment(comm), opcodes(opc) {}
  };

  struct tx
  {
    uint32_t version;
    std::vector<tx_input> vin;
    std::vector<tx_output> vout;
    std::vector<unsigned char> extra;
    uint64_t fee;
    std::vector<rct::ecdhTuple> ecdh_info;
    rct::rctSig signature;

    tx()
    {
      version = 0;
      fee = 0;
      signature.type = rct::RCTTypeCLSAG;
    }

    tx(uint32_t ver,
       const std::vector<tx_input> &inputs,
       const std::vector<tx_output> &outputs,
       const std::vector<unsigned char> &ext_data,
       uint64_t tx_fee,
       const std::vector<rct::ecdhTuple> &ecdh)
        : version(ver),
          vin(inputs),
          vout(outputs),
          extra(ext_data),
          fee(tx_fee),
          ecdh_info(ecdh) {}

    void getKeyFromBlockchain(rct::ctkey &a, size_t reference_index, SimpleLMDB db)
    {
      std::string key = std::to_string(reference_index);
      std::string blob = db.get("outputs", key);

      if (blob.size() != 64)
        throw std::runtime_error("Invalid output blob size");

      std::memcpy(a.mask.bytes, blob.data(), 32);
      std::memcpy(a.dest.bytes, blob.data() + 32, 32);
    }

    // helper to pick a random integer in [0, n)
    static size_t rand_index(size_t n)
    {
      static thread_local std::mt19937_64 gen{std::random_device{}()};
      std::uniform_int_distribution<size_t> dist(0, n - 1);
      return dist(gen);
    }

    // Build the mix‐ring for genRct:
    std::tuple<rct::ctkeyV, size_t> populate_ring_for_one_input(
        const rct::ctkey &actual_inPk_for_this_input, // The ctkey of the real output being spent
        int mixin,
        SimpleLMDB &db,                                    // Pass DB by reference
        const std::set<size_t> &used_decoys_global_indices // To avoid reusing decoys within the same TX
    )
    {
      size_t ring_size = static_cast<size_t>(mixin) + 1;
      if (ring_size < 1)
      { // Should not happen if mixin >= 0
        throw std::runtime_error("Ring size cannot be less than 1.");
      }

      rct::ctkeyV ring(ring_size); // This is THE ring for this one input
      size_t real_index = (ring_size > 1) ? rand_index(ring_size) : 0;

      uint64_t total_spendable_outputs = 0;
      try
      {
        total_spendable_outputs = db.count_fast("outputs");
        if (mixin > 0 && total_spendable_outputs < static_cast<uint64_t>(mixin))
        {
          throw std::runtime_error("Not enough outputs on chain for the desired mixin level.");
        }
      }
      catch (const std::runtime_error &e)
      {
        throw std::runtime_error("Failed to get output count for decoy selection: " + std::string(e.what()));
      }

      std::set<size_t> current_ring_decoy_indices = used_decoys_global_indices;

      for (size_t i = 0; i < ring_size; ++i)
      {
        if (i == real_index)
        {
          ring[i] = actual_inPk_for_this_input;
        }
        else
        {
          if (mixin == 0)
          { // Should ideally be caught by ring_size == 1 case
            // This case should not be hit if real_index logic is correct for ring_size 1
            // but as a safeguard:
            if (ring_size == 1)
              ring[i] = actual_inPk_for_this_input; // Ring of 1 is just the real input
            else
              throw std::logic_error("Trying to pick decoy with mixin 0 and ring_size > 1");
            continue;
          }
          if (total_spendable_outputs == 0)
          {
            throw std::runtime_error("No outputs available for decoys.");
          }

          int attempts = 0;
          const int max_attempts = 100; // To prevent infinite loops if pool is small
          bool decoy_found_and_placed = false;
          while (attempts < max_attempts && !decoy_found_and_placed)
          {
            attempts++;
            size_t random_global_output_idx = rand_index(total_spendable_outputs);

            // Crucial: Ensure this decoy isn't the real one being spent (if you can identify it globally)
            // and isn't already used in this transaction.
            // This requires `actual_inPk_for_this_input` to have a way to be compared against a global index
            // or its own global index known. For simplicity, we only check against used_decoys here.
            // A more robust check would involve knowing the global index of actual_inPk_for_this_input.

            if (current_ring_decoy_indices.count(random_global_output_idx))
            {
              continue; // Already used this decoy in this transaction, try again
            }

            try
            {
              getKeyFromBlockchain(ring[i], random_global_output_idx, db);
              current_ring_decoy_indices.insert(random_global_output_idx); // Mark as used for this TX
              decoy_found_and_placed = true;
            }
            catch (const std::runtime_error &e)
            {
              // E.g., "Key not found" or "Invalid output blob size". This decoy candidate is bad.
              // Log this, and try again for a different decoy.
              // std::cerr << "Warning: Failed to fetch decoy " << random_global_output_idx << ": " << e.what() << std::endl;
              if (attempts >= max_attempts)
              {
                throw std::runtime_error("Failed to find and fetch a valid decoy after " + std::to_string(max_attempts) + " attempts. Error: " + e.what());
              }
            }
          }
          if (!decoy_found_and_placed)
          {
            throw std::runtime_error("Could not secure a valid decoy for the ring.");
          }
        }
      }
      return std::make_tuple(ring, real_index);
    }

    template <typename T>
    static void append_pod(std::string &buf, const T &v)
    {
      const char *p = reinterpret_cast<const char *>(&v);
      buf.append(p, p + sizeof(T));
    }

    static void append_varint(std::string &buf, uint64_t x)
    {
      while (x >= 0x80)
      {
        buf.push_back(char((x & 0x7f) | 0x80));
        x >>= 7;
      }
      buf.push_back(char(x));
    }

    static void serialize_prefix(const tx &t, std::string &buf)
    {
      append_pod(buf, t.version);
      append_varint(buf, t.vin.size());
      for (auto const &in : t.vin)
      {
        buf.append(reinterpret_cast<const char *>(in.image.data), 32);
        append_varint(buf, in.key_offsets.size());
        for (auto off : in.key_offsets)
          append_varint(buf, off);
      }

      append_varint(buf, t.vout.size());
      for (auto const &out : t.vout)
      {
        buf.append(reinterpret_cast<const char *>(out.ephemeral_pub_key.data), 32);
        buf.append(reinterpret_cast<const char *>(out.commitment.bytes), 32);

        append_varint(buf, out.opcodes.size());
        if (!out.opcodes.empty())
        {
          buf.append(out.opcodes.data(), out.opcodes.size());
        }
      }

      append_varint(buf, t.extra.size());
      buf.append(reinterpret_cast<const char *>(t.extra.data()), t.extra.size());
      append_pod(buf, t.fee);
    }

    static void append_key(std::string &buf, const rct::key &k)
    {
      buf.append(reinterpret_cast<const char *>(k.bytes), 32);
    }

    static void serializeBulletproof(const rct::Bulletproof &proof, std::string &buf)
    {
      // Vectors
      append_varint(buf, proof.V.size());
      for (auto const &V_i : proof.V)
        append_key(buf, V_i);
      // Core elements
      append_key(buf, proof.A);
      append_key(buf, proof.S);
      append_key(buf, proof.T1);
      append_key(buf, proof.T2);
      append_key(buf, proof.taux);
      append_key(buf, proof.mu);
      // L and R vectors
      append_varint(buf, proof.L.size());
      for (auto const &L_i : proof.L)
        append_key(buf, L_i);
      append_varint(buf, proof.R.size());
      for (auto const &R_i : proof.R)
        append_key(buf, R_i);
    }

    static void serialize_clsag(const rct::clsag &c, std::string &buf)
    {
      // c.s (keyV - vector of scalars)
      append_varint(buf, c.s.size());
      for (const auto &s_i : c.s)
      {
        append_key(buf, s_i);
      }
      // c.c1 (key - scalar)
      append_key(buf, c.c1);
      // c.I (key - key image)
      append_key(buf, c.I);
      // c.D (key - auxiliary key image D/8)
      append_key(buf, c.D);
    }

    static void serialize_mgSig(const rct::mgSig &mg, std::string &buf)
    {
      // mg.ss (keyM - matrix of scalars)
      append_varint(buf, mg.ss.size()); // Number of columns
      if (!mg.ss.empty())
      {
        append_varint(buf, mg.ss[0].size()); // Number of rows
        for (const auto &col_vec : mg.ss)
        {
          for (const auto &s_ij : col_vec)
          {
            append_key(buf, s_ij);
          }
        }
      }
      else
      {
        append_varint(buf, 0); // 0 rows if 0 columns
      }

      // mg.cc (key - scalar)
      append_key(buf, mg.cc);

      // mg.II (keyV - vector of key images)
      append_varint(buf, mg.II.size());
      for (const auto &I_i : mg.II)
      {
        append_key(buf, I_i);
      }
    }

    static void serialize_rctSig(const rct::rctSig &rv, std::string &buf)
    {
      append_pod(buf, rv.type);

      // 1. Bulletproofs (Always for this type)
      append_varint(buf, rv.p.bulletproofs.size()); // Should be 1 for an aggregate proof
      for (const auto &bp : rv.p.bulletproofs)
      {
        serializeBulletproof(bp, buf);
      }

      // 2. CLSAGs (Always for this type)
      append_varint(buf, rv.p.CLSAGs.size()); // Number of inputs
      for (const auto &clsag_sig : rv.p.CLSAGs)
      {
        serialize_clsag(clsag_sig, buf);
      }

      // 3. PseudoOuts (C' for CLSAGs)
      append_varint(buf, rv.p.pseudoOuts.size()); // Should match number of inputs/CLSAGs
      for (const auto &po : rv.p.pseudoOuts)
      {
        append_key(buf, po);
      }

      // 4. MixRing (std::vector<ctkeyV> for simple types in Monero)
      // Assuming rv.mixRing is std::vector<ctkeyV> as populated by genRctSimple
      append_varint(buf, rv.mixRing.size()); // Number of input rings (should match CLSAGs.size())
      if (!rv.mixRing.empty())
      {
        append_varint(buf, rv.mixRing[0].size()); // Number of members in each ring (mixin + 1)
        for (const auto &ring_for_input : rv.mixRing)
        {
          if (ring_for_input.size() != rv.mixRing[0].size())
          {
            throw std::runtime_error("Inconsistent ring sizes in mixRing serialization.");
          }
          for (const auto &member_ctkey : ring_for_input)
          {
            append_key(buf, member_ctkey.dest);
            append_key(buf, member_ctkey.mask);
          }
        }
      }
      else
      {
        append_varint(buf, 0); // 0 ring members if 0 inputs
      }

      // 5. Transaction Fee
      append_pod(buf, rv.txnFee);
    }

    static rct::key get_prefix_hash(const tx &t)
    {
      std::string blob;
      serialize_prefix(t, blob);
      crypto::hash h;
      crypto::cn_fast_hash(blob.data(), blob.size(), h);
      rct::key k;
      std::memcpy(k.bytes, h.data, sizeof(h.data));
      return k;
    }

    static rct::key get_message_for_clsag(const rct::rctSig &rv)
    {
      std::vector<rct::key> intermediate_hashes_for_final_hash; // Will hold 3 keys
      intermediate_hashes_for_final_hash.reserve(3);

      // 1. rv.message (Prefix hash)
      intermediate_hashes_for_final_hash.push_back(rv.message);

      // 2. Hash of "rctSigBase" components
      // This blob MUST match what Monero's rctSig::serialize_rctsig_base would produce
      // for the given rv.type (RCTTypeCLSAG).
      std::string rctsig_base_blob;
      append_pod(rctsig_base_blob, rv.type);
      append_pod(rctsig_base_blob, rv.txnFee);

      append_varint(rctsig_base_blob, rv.ecdhInfo.size());
      for (const auto &ec : rv.ecdhInfo)
      {
        append_key(rctsig_base_blob, ec.mask);
        append_key(rctsig_base_blob, ec.amount);
      }

      append_varint(rctsig_base_blob, rv.outPk.size());
      for (const auto &opk_member : rv.outPk)
      { // opk_member is ctkey
        append_key(rctsig_base_blob, opk_member.dest);
        append_key(rctsig_base_blob, opk_member.mask);
      }

      // --- NEW: Add pseudoOuts and mixRing to rctsig_base_blob ---
      // (This assumes rv.type is already confirmed to be a "simple" type like RCTTypeCLSAG)
      // a. PseudoOuts (from rv.p)
      append_varint(rctsig_base_blob, rv.p.pseudoOuts.size());
      for (const auto &po : rv.p.pseudoOuts)
      {
        append_key(rctsig_base_blob, po);
      }

      // b. MixRing (direct member of rctSig for simple types: std::vector<ctkeyV>)
      append_varint(rctsig_base_blob, rv.mixRing.size()); // Number of input rings
      if (!rv.mixRing.empty())
      {
        append_varint(rctsig_base_blob, rv.mixRing[0].size()); // Number of members in each ring
        for (const auto &ring_for_input : rv.mixRing)
        {
          // Optional: Add a check here if all rings in mixRing must have the same size
          // if (ring_for_input.size() != rv.mixRing[0].size()) { /* error */ }
          for (const auto &member_ctkey : ring_for_input)
          {
            append_key(rctsig_base_blob, member_ctkey.dest);
            append_key(rctsig_base_blob, member_ctkey.mask);
          }
        }
      }
      else
      {
        append_varint(rctsig_base_blob, 0); // 0 members if 0 rings
      }
      // --- End of NEW additions to rctsig_base_blob ---

      crypto::hash h_rctsig_base;
      crypto::cn_fast_hash(rctsig_base_blob.data(), rctsig_base_blob.size(), h_rctsig_base);
      intermediate_hashes_for_final_hash.push_back(rct::hash2rct(h_rctsig_base));

      // 3. Hash of Bulletproof components (A,S,T1,T2,taux,mu,L,R,a,b,t)
      std::string bp_components_blob;
      if (!rv.p.bulletproofs.empty())
      { // Should be one for RCTTypeCLSAG
        const auto &proof = rv.p.bulletproofs[0];
        append_key(bp_components_blob, proof.A);
        append_key(bp_components_blob, proof.S);
        append_key(bp_components_blob, proof.T1);
        append_key(bp_components_blob, proof.T2);
        append_key(bp_components_blob, proof.taux);
        append_key(bp_components_blob, proof.mu);
        append_varint(bp_components_blob, proof.L.size());
        for (const auto &l_val : proof.L)
          append_key(bp_components_blob, l_val);
        append_varint(bp_components_blob, proof.R.size());
        for (const auto &r_val : proof.R)
          append_key(bp_components_blob, r_val);
        append_key(bp_components_blob, proof.a);
        append_key(bp_components_blob, proof.b);
        append_key(bp_components_blob, proof.t);
      }
      crypto::hash h_bp_components;
      crypto::cn_fast_hash(bp_components_blob.data(), bp_components_blob.size(), h_bp_components);
      intermediate_hashes_for_final_hash.push_back(rct::hash2rct(h_bp_components));

      // 4. Final hash: Hash the concatenation of the three intermediate_hashes
      // This now matches the simplified Monero mlsag_prehash behavior.
      std::string final_blob_to_hash;
      for (const auto &k : intermediate_hashes_for_final_hash)
      {
        append_key(final_blob_to_hash, k);
      }
      crypto::hash final_message_hash_val;
      crypto::cn_fast_hash(final_blob_to_hash.data(), final_blob_to_hash.size(), final_message_hash_val);
      return rct::hash2rct(final_message_hash_val);
    }

    rct::rctSig make(
        // const rct::ctkeyV &inSk, // genRctSimple takes std::vector<ctkey> inSk
        const std::vector<rct::ctkey> &inSk, // For genRctSimple, one per input
        // const rct::ctkeyV &inPk, // genRctSimple can take inPk to populate mixRing internally
        const std::vector<rct::ctkey> &inPk, // Public keys corresponding to inSk
        const rct::keyV &destinations,
        // const std::vector<uint64_t> &amounts, // genRctSimple takes inAmounts and outAmounts
        const std::vector<uint64_t> &inAmounts,  // One per input
        const std::vector<uint64_t> &outAmounts, // One per output
        const rct::keyV &amount_keys,            // Per output for ECDH
        int mixin,                               // mixin level (number of decoys, so ring size is mixin + 1)
        // const rct::RCTConfig &config, // We'll define it here
        hw::device &hwdev)
    {
      SimpleLMDB db("./lmdb_data"); // Consider passing db as const& or managing its lifecycle
      rct::key msg = get_prefix_hash(*this);

      rct::RCTConfig rct_config;
      rct_config.range_proof_type = rct::RangeProofPaddedBulletproof; // Or your chosen BP type
      rct_config.bp_version = 3;                                      // For RCTTypeCLSAG in Monero.

      std::vector<unsigned int> indices(inSk.size());
      rct::ctkeyM an_mixRing(inSk.size()); // ctkeyM is std::vector<ctkeyV>

      std::set<size_t> used_decoys_for_this_tx;

      for (size_t i = 0; i < inSk.size(); ++i)
      {
        // Call the new function for each input
        auto [single_ring_for_input_i, real_idx_for_input_i] =
            populate_ring_for_one_input(inPk[i], mixin, db, used_decoys_for_this_tx);

        an_mixRing[i] = single_ring_for_input_i; // Assign the ctkeyV ring
        indices[i] = static_cast<unsigned int>(real_idx_for_input_i);

        // Update the set of used decoys for the next input's ring construction
        // by adding the decoys used in 'single_ring_for_input_i'.
        for (size_t k = 0; k < single_ring_for_input_i.size(); ++k)
        {
          if (k != real_idx_for_input_i)
          {
            // This requires that getKeyFromBlockchain could return the global index it fetched,
            // or that you store it somehow. For now, this part is tricky without more info
            // on how your decoy indices are managed *after* fetching.
            // A simpler (but less robust against collisions if rand_index is bad)
            // way is not to update used_decoys_for_this_tx from here and rely on
            // the inner check of populate_ring_for_one_input if it had access to a tx-global set.
            // The passed `used_decoys_for_this_tx` to `populate_ring_for_one_input` handles this.
          }
        }
      }
      rct::ctkeyV outSk; // genRctSimple will populate this

      return rct::genRctSimple(
          msg,
          inSk,
          destinations,
          inAmounts,
          outAmounts,
          this->fee,
          an_mixRing,
          amount_keys,
          indices,
          outSk,
          rct_config,
          hwdev);
    }

    bool ver(bool check_semantics, bool check_signature)
    {
      const rct::rctSig &rv = this->signature;
      SimpleLMDB db("./lmdb_data"); // Consider passing or making member

      const int EXPECTED_TX_TYPE = rct::RCTTypeCLSAG; // Or rct::RCTTypeBulletproof2 if it maps to CLSAG+BP for you

      if (check_semantics)
      {
        if (rv.type != EXPECTED_TX_TYPE)
        {
          std::cout << "Unsupported rctSig type, expected CLSAG/BP type." << std::endl;
          return false;
        }

        // Semantic checks for Bulletproofs and CLSAGs
        // Number of outputs should match number of amounts proven by Bulletproofs
        // Monero's n_bulletproof_amounts sums up V.size() from all BP structs. If you have one aggregate BP:
        if (rv.p.bulletproofs.empty() || rv.outPk.size() != rct::n_bulletproof_amounts(rv.p.bulletproofs[0]))
        {
          std::cout << "Mismatched output count and bulletproof amounts." << std::endl;
          return false;
        }
        // Number of CLSAGs should match number of inputs (vin) and pseudoOuts
        if (rv.p.CLSAGs.size() != this->vin.size() || rv.p.CLSAGs.size() != rv.p.pseudoOuts.size())
        {
          std::cout << "Mismatched CLSAGs, inputs, or pseudoOuts." << std::endl;
          return false;
        }
        // mixRing should have one ring per CLSAG
        if (rv.mixRing.size() != rv.p.CLSAGs.size())
        {
          std::cout << "Mismatched mixRing and CLSAGs." << std::endl;
          return false;
        }
        // ECDH info should match number of outputs
        if (rv.outPk.size() != rv.ecdhInfo.size())
        {
          std::cout << "Mismatched output fields (ecdhInfo)" << std::endl;
          return false;
        }

        // Bulletproof verification
        // Monero typically verifies all Bulletproofs in a tx together.
        // If rv.p.bulletproofs contains a single aggregate proof:
        if (!rv.p.bulletproofs.empty())
        {
          if (!rct::verBulletproof(rv.p.bulletproofs[0]))
          { // Pass the single Bulletproof struct
            std::cout << "Bulletproof verification failed." << std::endl;
            return false;
          }
        }
        else
        {
          std::cout << "No bulletproofs found for verification." << std::endl;
          return false;
        }
      }

      if (check_signature)
      {
        if (rv.type != EXPECTED_TX_TYPE)
        { /* error */
          return false;
        }

        rct::key message_for_clsags = get_message_for_clsag(rv);

        // CLSAG verification (one per input)
        for (size_t i = 0; i < rv.p.CLSAGs.size(); ++i)
        {
          if (i >= rv.mixRing.size() || i >= rv.p.pseudoOuts.size())
          {
            std::cout << "Indexing error for CLSAG verification." << std::endl;
            return false; // Should be caught by semantic checks earlier
          }
          // verRctCLSAGSimple expects: const key &message, const clsag &sig, const ctkeyV & pubs (ring for this input), const key & C_offset (pseudoOut for this input)
          if (!rct::verRctCLSAGSimple(message_for_clsags, rv.p.CLSAGs[i], rv.mixRing[i], rv.p.pseudoOuts[i]))
          {
            std::cout << "CLSAG signature verification failed for input " << i << std::endl;
            return false;
          }
        }
      }

      // Phase 3: Key Image Reuse - check against database
      for (auto const &in : vin)
      {
        // raw 32‑byte key_image blob
        std::string ki_blob(reinterpret_cast<const char *>(in.image.data), 32);

        try
        {
          // if this succeeds, we have a reuse
          db.get("key_images", ki_blob);
          std::cout << "Key image reuse detected\n";
          return false;
        }
        catch (const std::runtime_error &e)
        {
          // expected: key not found → safe to proceed
          if (std::string(e.what()) != "Key not found")
            throw; // real DB error
        }
      }

      // If we reach here, no reuse: now record them
      for (auto const &in : vin)
      {
        std::string ki_blob(reinterpret_cast<const char *>(in.image.data), 32);
        db.put("key_images", ki_blob, "");
      }
      return true;
    }

    std::string serialize_tx() const
    {
      std::string buf;
      // Serialize;
      serialize_prefix(*this, buf);
      // ECDH info
      append_varint(buf, ecdh_info.size());
      for (auto const &e : ecdh_info)
      {
        buf.append(reinterpret_cast<const char *>(e.mask.bytes), 32);
        buf.append(reinterpret_cast<const char *>(e.amount.bytes), 32);
      }

      // RCT signature
      serialize_rctSig(signature, buf);

      return buf;
    }

    static tx deserialize_tx(const std::string &blob)
    {
      size_t offset = 0;
      auto require = [&](size_t sz)
      {
        if (offset + sz > blob.size())
          throw std::runtime_error("Blob too small for tx deserialization");
      };
      // readers
      auto read_pod = [&](auto &out)
      {
        require(sizeof(out));
        std::memcpy(&out, blob.data() + offset, sizeof(out));
        offset += sizeof(out);
      };
      auto read_varint = [&]
      {
        uint64_t x = 0;
        int shift = 0;
        while (true)
        {
          require(1);
          uint8_t byte = static_cast<uint8_t>(blob[offset++]);
          x |= uint64_t(byte & 0x7F) << shift;
          if ((byte & 0x80) == 0)
            break;
          shift += 7;
        }
        return x;
      };
      auto read_key = [&](rct::key &k)
      {
        require(32);
        std::memcpy(k.bytes, blob.data() + offset, 32);
        offset += 32;
      };
      auto read_pubkey = [&](crypto::public_key &pk)
      {
        require(32);
        std::memcpy(pk.data, blob.data() + offset, 32);
        offset += 32;
      };

      // New: specific reader for crypto::public_key's .data
      auto read_actual_pubkey = [&](crypto::public_key &pk_data_owner)
      {
        require(32);
        std::memcpy(pk_data_owner.data, blob.data() + offset, 32);
        offset += 32;
      };
      // New: specific reader for crypto::key_image's .data
      auto read_actual_key_image = [&](crypto::key_image &ki_data_owner)
      {
        require(32);
        std::memcpy(ki_data_owner.data, blob.data() + offset, 32);
        offset += 32;
      };

      tx t;
      // prefix
      read_pod(t.version);
      // vin
      {
        uint64_t n_vin = read_varint();
        t.vin.resize(n_vin);
        for (auto &in : t.vin)
        {
          // in.amount = read_varint(); // Assuming this was intentionally removed for privacy
          read_actual_key_image(in.image); // Use specific reader
          uint64_t m_offsets = read_varint();
          in.key_offsets.resize(m_offsets);
          for (size_t i = 0; i < m_offsets; ++i)
            in.key_offsets[i] = read_varint();
        }
      }
      // vout
      {
        uint64_t n_vout = read_varint();
        t.vout.resize(n_vout);
        for (auto &out : t.vout)
        {
          read_actual_pubkey(out.ephemeral_pub_key); // Use specific reader
          read_key(out.commitment);

          uint64_t opcodes_len = read_varint();
          if (opcodes_len > 0)
          {
            require(opcodes_len); // Make sure enough data exists
            out.opcodes.assign(blob.data() + offset, blob.data() + offset + opcodes_len);
            offset += opcodes_len;
          }
          else
          {
            out.opcodes.clear();
          }
        }
      }
      // extra
      {
        uint64_t m_extra = read_varint();
        require(m_extra);
        t.extra.assign(blob.begin() + offset, blob.begin() + offset + m_extra);
        offset += m_extra;
      }
      // fee
      read_pod(t.fee);
      // ecdh_info
      {
        uint64_t n_ecdh = read_varint();
        t.ecdh_info.resize(n_ecdh);
        for (auto &e : t.ecdh_info)
        {
          read_key(e.mask);
          read_key(e.amount);
        }
      }

      // rctSig
      {
        read_pod(t.signature.type);
        if (t.signature.type != rct::RCTTypeCLSAG && t.signature.type != rct::RCTTypeBulletproof2)
        { // Check against your chosen type ID(s)
          throw std::runtime_error("deserialize_tx: Attempting to deserialize non-CLSAG/BP type as CLSAG/BP.");
        }

        // 1. Bulletproofs
        uint64_t bp_count = read_varint();
        t.signature.p.bulletproofs.resize(bp_count);
        for (auto &bp : t.signature.p.bulletproofs)
        {
          // ... (your existing Bulletproof deserialization: V, A, S, T1, T2, taux, mu, L, R, a, b, t)
          uint64_t V_count = read_varint();
          bp.V.resize(V_count);
          for (auto &v_i : bp.V)
            read_key(v_i);
          read_key(bp.A);
          read_key(bp.S);
          read_key(bp.T1);
          read_key(bp.T2);
          read_key(bp.taux);
          read_key(bp.mu);
          uint64_t L_count = read_varint();
          bp.L.resize(L_count);
          for (auto &l_i : bp.L)
            read_key(l_i);
          uint64_t R_count_bp = read_varint();
          bp.R.resize(R_count_bp);
          for (auto &r_i : bp.R)
            read_key(r_i);
          read_key(bp.a);
          read_key(bp.b);
          read_key(bp.t);
        }

        // 2. CLSAGs
        uint64_t clsag_count = read_varint();
        t.signature.p.CLSAGs.resize(clsag_count);
        for (auto &clsag_sig : t.signature.p.CLSAGs)
        {
          // ... (your existing CLSAG deserialization: s, c1, I, D)
          uint64_t s_count = read_varint();
          clsag_sig.s.resize(s_count);
          for (auto &s_i : clsag_sig.s)
            read_key(s_i);
          read_key(clsag_sig.c1);
          read_key(clsag_sig.I);
          read_key(clsag_sig.D);
        }

        // 3. PseudoOuts
        uint64_t po_count = read_varint();
        t.signature.p.pseudoOuts.resize(po_count);
        for (auto &po_key : t.signature.p.pseudoOuts)
        {
          read_key(po_key);
        }

        // 4. MixRing
        // Assuming t.signature.mixRing is std::vector<ctkeyV>
        uint64_t num_input_rings = read_varint();
        uint64_t ring_members_per_ring = 0;
        if (num_input_rings > 0)
        {
          ring_members_per_ring = read_varint();
        }
        t.signature.mixRing.resize(num_input_rings);
        for (uint64_t i = 0; i < num_input_rings; ++i)
        {
          t.signature.mixRing[i].resize(ring_members_per_ring);
          for (uint64_t j = 0; j < ring_members_per_ring; ++j)
          {
            read_key(t.signature.mixRing[i][j].dest);
            read_key(t.signature.mixRing[i][j].mask);
          }
        }

        // 5. Transaction Fee
        read_pod(t.signature.txnFee);
      }
      return t;
    }
  };

}
#endif