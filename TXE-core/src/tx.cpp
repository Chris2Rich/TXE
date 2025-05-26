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
    
    rct::rctSig make(){
        return rct::genRct();
    }
};

}