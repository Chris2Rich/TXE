#include <crypto/crypto.h>
#include <ringct/rctOps.h>
#include <ringct/rctTypes.h>
#include <ringct/rctSigs.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <functional>

namespace TXE {

template<typename T>
  void append_pod(std::string &buf, const T &v) {
    const char *p = reinterpret_cast<const char*>(&v);
    buf.append(p, p + sizeof(T));
  }

  void append_varint(std::string &buf, uint64_t x) {
    while (x >= 0x80) {
      buf.push_back(char((x & 0x7f) | 0x80));
      x >>= 7;
    }
    buf.push_back(char(x));
  }

  void serialize_prefix(const tx &t, std::string &buf) {
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

  rct::key get_prefix_hash(const tx &t) {
    std::string blob;
    serialize_prefix(t, blob);
    crypto::hash h;
    crypto::cn_fast_hash(blob.data(), blob.size(), h);
    rct::key k;
    std::memcpy(k.bytes, h.data, sizeof(h.data));
    return k;
  }

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

struct tx_input {
    uint64_t amount;
    crypto::key_image image;
    std::vector<uint64_t> key_offsets;

    tx_input() : amount(0) {}
    tx_input(const crypto::key_image& img, const std::vector<uint64_t>& offsets, uint64_t amt = 0)
        : amount(amt), image(img), key_offsets(offsets) {}
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

    bool ver(){
        
    }
};

}