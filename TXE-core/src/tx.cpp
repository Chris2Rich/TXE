#ifndef __tx
#define __tx

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

namespace TXE {

struct tx_input {
    uint64_t amount;
    crypto::key_image image;
    std::vector<uint64_t> key_offsets;

    tx_input() : amount(0) {}
    tx_input(const crypto::key_image& img, const std::vector<uint64_t>& offsets, uint64_t amt = 0)
        : amount(amt), image(img), key_offsets(offsets) {}
};

struct tx_output {
    crypto::public_key ephemeral_pub_key;
    rct::key commitment;
    rct::Bulletproof proof;
    std::string opcodes;

    tx_output() = default;
    tx_output(const crypto::public_key& pk,
              const rct::key& comm,
              const rct::Bulletproof& rp,
              const std::string& opc = "")
        : ephemeral_pub_key(pk), commitment(comm), proof(rp), opcodes(opc) {}
};

struct tx {
    uint32_t version;
    std::vector<tx_input> vin;
    std::vector<tx_output> vout;
    std::vector<unsigned char> extra;
    uint64_t fee;
    std::vector<rct::ecdhTuple> ecdh_info;
    std::vector<rct::key> pseudo_outs;
    std::vector<rct::clsag> input_signatures;
    rct::rctSig signature;

    tx() : version(2), fee(0) {}

    tx(uint32_t ver,
       const std::vector<tx_input>& inputs,
       const std::vector<tx_output>& outputs,
       const std::vector<unsigned char>& ext_data,
       uint64_t tx_fee,
       const std::vector<rct::ecdhTuple>& ecdh,
       const std::vector<rct::key>& pseudos,
       const std::vector<rct::clsag>& sigs)
        : version(ver),
          vin(inputs),
          vout(outputs),
          extra(ext_data),
          fee(tx_fee),
          ecdh_info(ecdh),
          pseudo_outs(pseudos),
          input_signatures(sigs) {}

    template<typename T>
      static void append_pod(std::string &buf, const T &v) {
        const char *p = reinterpret_cast<const char*>(&v);
        buf.append(p, p + sizeof(T));
      }

      static void append_varint(std::string &buf, uint64_t x) {
        while (x >= 0x80) {
          buf.push_back(char((x & 0x7f) | 0x80));
          x >>= 7;
        }
        buf.push_back(char(x));
      }

      static void serialize_prefix(const tx &t, std::string &buf) {
        append_pod(buf, t.version);
        append_varint(buf, t.vin.size());
        for (auto const &in : t.vin) {
          buf.append(reinterpret_cast<const char*>(in.image.data), 32);
          append_varint(buf, in.key_offsets.size());
          for (auto off : in.key_offsets)
            append_varint(buf, off);
        }

        append_varint(buf, t.vout.size());
        for (auto const &out : t.vout) {
          buf.append(reinterpret_cast<const char*>(out.ephemeral_pub_key.data), 32);
          buf.append(reinterpret_cast<const char*>(out.commitment.bytes), 32);
        }

        append_varint(buf, t.extra.size());
        buf.append(reinterpret_cast<const char*>(t.extra.data()), t.extra.size());
        append_pod(buf, t.fee);
      }

          static void append_key(std::string& buf, const rct::key& k) {
        buf.append(reinterpret_cast<const char*>(k.bytes), 32);
    }

    static void serializeBulletproof(const rct::Bulletproof& proof, std::string& buf) {
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

    static void serialize_clsag(const rct::clsag& c, std::string& buf) {
        // Key image and public keys
        append_key(buf, c.P);
        // "D" commitment
        append_key(buf, c.D);
        // Challenge scalar
        append_key(buf, c.c1);
        // Responses
        append_key(buf, c.r1);
        // Vector of public keys (I)
        append_varint(buf, c.I.size());
        for (auto const &Ii : c.I)
            append_key(buf, Ii.dest);
        // s-values
        append_varint(buf, c.s.size());
        for (auto const &si : c.s)
            append_key(buf, si);
    }

    static void serialize_rctSig(const rct::rctSig& rv, std::string& buf) {
        // Type
        append_pod(buf, rv.type);
        // Range proofs
        append_varint(buf, rv.p.rangeSigs.size());
        for (auto const &rp : rv.p.rangeSigs)
            serializeBulletproof(rp, buf);
        // MGs (CLSAGs)
        append_varint(buf, rv.p.MGs.size());
        for (auto const &mg : rv.p.MGs)
            serialize_clsag(mg, buf);
        // Fee commitment
        append_key(buf, rv.txnFee);
    }

      static rct::key get_prefix_hash(const tx &t) {
        std::string blob;
        serialize_prefix(t, blob);
        crypto::hash h;
        crypto::cn_fast_hash(blob.data(), blob.size(), h);
        rct::key k;
        std::memcpy(k.bytes, h.data, sizeof(h.data));
        return k;
      }
    
    rct::rctSig make(
        const rct::ctkeyV&        inSk,
        const rct::ctkeyV&        inPk,
        const rct::keyV&          destinations,
        const std::vector<uint64_t>& amounts,
        const rct::keyV&          amount_keys,
        int                       mixin,
        const rct::RCTConfig&     config,
        hw::device&               hwdev
    ) const {
        // 1) Pre‐MLSAG hash (the “message”)
        rct::key msg = get_prefix_hash(*this);

        // 2) Fetch mixRing + real index via your hook:
        auto [mixRing, real_index] = tktkpopulate(inPk, mixin);

        // 3) Prepare output secret‐mask vector
        rct::ctkeyV outSk;
        outSk.resize(destinations.size());

        // 4) Call Monero’s core genRct
        return rct::genRct(
        msg,            // message
        inSk,           // input secret ctkeys
        destinations,   // output masks
        amounts,        // clear amounts (+fee if any)
        mixRing,        // mixin ring
        amount_keys,    // ECDH amount keys
        real_index,     // real‐index in the ring
        outSk,          // OUTPUT: per‐output secret ctkeys
        config,         // RCTConfig flags
        hwdev           // device for ecdhEncode
        );
    }

  bool ver(const rct::rctSig &rv, bool check_semantics, bool check_signature) {
      if (check_semantics) {
          if (rv.type != rct::RCTTypeFull) {
              std::cout << "Unsupported rctSig type" << std::endl;
              return false;
          }

          if (rv.outPk.size() != rv.p.rangeSigs.size() || rv.outPk.size() != rv.ecdhInfo.size()) {
              std::cout << "Mismatched output fields" << std::endl;
              return false;
          }

          // Parallel verification of bulletproofs
          for (size_t i = 0; i < rv.outPk.size(); ++i) {
              if (!rct::verRange(rv.outPk[i].mask, rv.p.rangeSigs[i])) {
                  std::cout << "Invalid range proof at index " << i << std::endl;
                  return false;
              }
          }
      }

      // Phase 2: Ring signature / key image check
      if (check_signature) {
          if (rv.p.MGs.size() != 1) {
              std::cout << "Invalid number of MGs" << std::endl;
              return false;
          }

          rct::key pre_mlsag_hash = get_prefix_hash(*this);
          rct::key fee_commitment = rct::scalarmultH(rct::d2h(rv.txnFee));

          if (!rct::verRctMG(rv.p.MGs[0], rv.mixRing, rv.outPk, fee_commitment, pre_mlsag_hash)) {
              std::cout << "Ring signature verification failed" << std::endl;
              return false;
          }
      }

      // Phase 3: Key Image Reuse - check against database

      return true;
  }

  std::string serialize_tx() const {
        std::string buf;
        // Serialize;
        serialize_prefix(*this, buf);
        // ECDH info
        append_varint(buf, ecdh_info.size());
        for (auto const &e : ecdh_info) {
            buf.append(reinterpret_cast<const char*>(e.mask.bytes), 32);
            buf.append(reinterpret_cast<const char*>(e.amount.bytes), 32);
        }

        // Pseudo outputs
        append_varint(buf, pseudo_outs.size());
        for (auto const &p : pseudo_outs)
            buf.append(reinterpret_cast<const char*>(p.bytes), 32);

        // Input CLSAGs
        append_varint(buf, input_signatures.size());
        for (auto const &cls : input_signatures) {
            serialize_clsag(cls, buf);
        }

        // RCT signature
        serialize_rctSig(signature, buf);

        return buf;
    }

static tx deserialize_tx(const std::string& blob) {
        size_t offset = 0;
        auto require = [&](size_t sz) {
            if (offset + sz > blob.size())
                throw std::runtime_error("Blob too small for tx deserialization");
        };
        // readers
        auto read_pod = [&](auto& out) {
            require(sizeof(out));
            std::memcpy(&out, blob.data() + offset, sizeof(out));
            offset += sizeof(out);
        };
        auto read_varint = [&]() {
            uint64_t x = 0;
            int shift = 0;
            while (true) {
                require(1);
                uint8_t byte = static_cast<uint8_t>(blob[offset++]);
                x |= uint64_t(byte & 0x7F) << shift;
                if ((byte & 0x80) == 0) break;
                shift += 7;
            }
            return x;
        };
        auto read_key = [&](rct::key& k) {
            require(32);
            std::memcpy(k.bytes, blob.data() + offset, 32);
            offset += 32;
        };
        auto read_pubkey = [&](crypto::public_key& pk) {
            require(32);
            std::memcpy(pk.data, blob.data() + offset, 32);
            offset += 32;
        };
        tx t;
        // prefix
        read_pod(t.version);
        // vin
        {
            uint64_t n = read_varint(); t.vin.resize(n);
            for (auto& in : t.vin) {
                in.amount = read_varint();
                read_pubkey(in.image);
                uint64_t m = read_varint(); in.key_offsets.resize(m);
                for (size_t i = 0; i < m; ++i)
                    in.key_offsets[i] = read_varint();
            }
        }
        // vout
        {
            uint64_t n = read_varint(); t.vout.resize(n);
            for (auto& out : t.vout) {
                read_pubkey(out.ephemeral_pub_key);
                read_key(out.commitment);
                // Bulletproofs and opcodes are in RCTSig
            }
        }
        // extra
        {
            uint64_t m = read_varint();
            require(m);
            t.extra.assign(blob.begin()+offset, blob.begin()+offset+m);
            offset += m;
        }
        // fee
        read_pod(t.fee);
        // ecdh_info
        {
            uint64_t n = read_varint(); t.ecdh_info.resize(n);
            for (auto& e : t.ecdh_info) { read_key(e.mask); read_key(e.amount); }
        }
        // pseudo_outs
        {
            uint64_t n = read_varint(); t.pseudo_outs.resize(n);
            for (auto& p : t.pseudo_outs) read_key(p);
        }
        // CLSAGs
        {
            uint64_t n = read_varint(); t.input_signatures.resize(n);
            for (auto& c : t.input_signatures) {
                read_key(c.P); read_key(c.D); read_key(c.c1); read_key(c.r1);
                uint64_t I = read_varint(); c.I.resize(I);
                for (auto& i : c.I) read_key(i.dest);
                uint64_t S = read_varint(); c.s.resize(S);
                for (auto& s : c.s) read_key(s);
            }
        }
        // rctSig
        {
            read_pod(t.signature.type);
            // rangeSigs
            uint64_t R = read_varint(); t.signature.p.rangeSigs.resize(R);
            for (auto& bp : t.signature.p.rangeSigs) {
                uint64_t V = read_varint(); bp.V.resize(V);
                for (auto& v : bp.V) read_key(v);
                read_key(bp.A); read_key(bp.S);
                read_key(bp.T1); read_key(bp.T2);
                read_key(bp.taux); read_key(bp.mu);
                uint64_t L = read_varint(); bp.L.resize(L);
                for (auto& l : bp.L) read_key(l);
                uint64_t R2 = read_varint(); bp.R.resize(R2);
                for (auto& r : bp.R) read_key(r);
            }
            // MGs
            uint64_t M = read_varint(); t.signature.p.MGs.resize(M);
            for (auto& mg : t.signature.p.MGs) {
                read_key(mg.P); read_key(mg.D);
                read_key(mg.c1); read_key(mg.r1);
                uint64_t I = read_varint(); mg.I.resize(I);
                for (auto& i : mg.I) read_key(i.dest);
                uint64_t S = read_varint(); mg.s.resize(S);
                for (auto& s : mg.s) read_key(s);
            }
            // fee comm
            read_key(t.signature.txnFee);
        }
        return t;
    }

};

}
#endif