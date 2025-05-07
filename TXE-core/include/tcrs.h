      
#ifndef _TCRS_H
#define _TCRS_H

#include <string>
#include <vector>
#include <map>
#include "tcrs_types.h"

struct tcrs{
    virtual ~tcrs() = default; // Important for polymorphism if TCRSImpl is used via tcrs*

    virtual bool system_setup(PublicParameters& trk_out, int security_parameter_k = 128) = 0;

    virtual bool gen_key(const PublicParameters& trk,
                 PartialPrivateKey& psk_for_member_out,
                 UserSecretKey& sk_out,
                 UserPublicKey& pk_out) = 0;

    virtual bool sign(const PublicParameters& trk,
              const UserSecretKey& sk_signer,
              const UserPublicKey& pk_signer,
              const std::vector<UserPublicKey>& rl_pk_list,
              const std::string& message,
              const std::string& event_id,
              Signature& sig_out) = 0;

    virtual bool verify(const PublicParameters& trk,
                const std::vector<UserPublicKey>& rl_pk_list,
                const std::string& message,
                const std::string& event_id,
                const Signature& sig) = 0;

    virtual std::string trace_user(const PublicParameters& trk,
                           const std::vector<UserPublicKey>& rl_pk_list,
                           const std::string& m1,
                           const Signature& sig1,
                           const std::string& m2,
                           const Signature& sig2,
                           const std::string& event_id,
                           const std::map<std::string, PartialPrivateKey>& sL_database_or_psk_db) = 0;
};

#endif // _TCRS_H

    