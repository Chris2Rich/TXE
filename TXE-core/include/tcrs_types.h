#ifndef TCRS_TYPES_H
#define TCRS_TYPES_H

#include <string>
#include <vector>
#include <stdexcept> // For runtime_error

extern "C" {
#include <relic/relic.h>
}

// Error checking macro for RELIC calls
#define RLC_CHK(code)                                     \
    do {                                                  \
        if ((code) != RLC_OK) {                           \
            relic_error_print();                          \
            throw std::runtime_error("RELIC API Error in " __FILE__ ":" + std::to_string(__LINE__));  \
        }                                                 \
    } while (0)

std::string bn_to_string_custom(const bn_t bn) {
    int len = bn_size_bin(bn);
    std::vector<unsigned char> buf(len);
    bn_write_bin(buf.data(), len, bn);
    return std::string(buf.begin(), buf.end());
}

void string_to_bn_custom(bn_t bn, const std::string& s) {
    RLC_CHK(bn_read_bin(bn, (unsigned char*)s.data(), s.length()));
}

std::string g1_to_string_custom(const g1_t g1_el) {
    // Use compression (1) if appropriate and consistently
    int len = g1_size_bin(g1_el, 1);
    std::vector<unsigned char> buf(len);
    g1_write_bin(buf.data(), len, g1_el, 1);
    return std::string(buf.begin(), buf.end());
}

void string_to_g1_custom(g1_t g1_el, const std::string& s) {
    RLC_CHK(g1_read_bin(g1_el, (unsigned char*)s.data(), s.length()));
}

std::string gt_to_string_custom(const gt_t gt_el) {
    int len = gt_size_bin(gt_el, 1);
    std::vector<unsigned char> buf(len);
    gt_write_bin(buf.data(), len, gt_el, 1);
    return std::string(buf.begin(), buf.end());
}

void string_to_gt_custom(gt_t gt_el, const std::string& s) {
    RLC_CHK(gt_read_bin(gt_el, (unsigned char*)s.data(), s.length()));
}


// --- PublicParameters ---
PublicParameters::PublicParameters() {
    bn_new(q); g1_new(g); g1_new(g1); g1_new(g2); g1_new(vau); g1_new(psi);
    g1_new(dollar); g1_new(mu); g1_new(tau); g1_new(chi); g1_new(kappa);
}
PublicParameters::~PublicParameters() {
    bn_free(q); g1_free(g); g1_free(g1); g1_free(g2); g1_free(vau); g1_free(psi);
    g1_free(dollar); g1_free(mu); g1_free(tau); g1_free(chi); g1_free(kappa);
}
PublicParameters::PublicParameters(const PublicParameters& other) : PublicParameters() { // Delegate to default constructor
    *this = other; // Use assignment operator
}
PublicParameters& PublicParameters::operator=(const PublicParameters& other) {
    if (this == &other) return *this;
    bn_copy(q, other.q); g1_copy(g, other.g); g1_copy(g1, other.g1); g1_copy(g2, other.g2);
    g1_copy(vau, other.vau); g1_copy(psi, other.psi); g1_copy(dollar, other.dollar);
    g1_copy(mu, other.mu); g1_copy(tau, other.tau); g1_copy(chi, other.chi); g1_copy(kappa, other.kappa);
    return *this;
}
std::string PublicParameters::serialize() const {
    std::string s;
    s += bn_to_string_custom(q) + "|"; // Use a delimiter
    s += g1_to_string_custom(g) + "|"; s += g1_to_string_custom(g1) + "|"; s += g1_to_string_custom(g2) + "|";
    s += g1_to_string_custom(vau) + "|"; s += g1_to_string_custom(psi) + "|"; s += g1_to_string_custom(dollar) + "|";
    s += g1_to_string_custom(mu) + "|"; s += g1_to_string_custom(tau) + "|"; s += g1_to_string_custom(chi) + "|";
    s += g1_to_string_custom(kappa);
    return s;
}
void PublicParameters::deserialize(const std::string& s) {
    std::stringstream ss(s);
    std::string item;
    std::getline(ss, item, '|'); string_to_bn_custom(q, item);
    std::getline(ss, item, '|'); string_to_g1_custom(g, item); std::getline(ss, item, '|'); string_to_g1_custom(g1, item);
    std::getline(ss, item, '|'); string_to_g1_custom(g2, item); std::getline(ss, item, '|'); string_to_g1_custom(vau, item);
    std::getline(ss, item, '|'); string_to_g1_custom(psi, item); std::getline(ss, item, '|'); string_to_g1_custom(dollar, item);
    std::getline(ss, item, '|'); string_to_g1_custom(mu, item); std::getline(ss, item, '|'); string_to_g1_custom(tau, item);
    std::getline(ss, item, '|'); string_to_g1_custom(chi, item); std::getline(ss, item, '|'); string_to_g1_custom(kappa, item);
}

// --- UserPublicKey ---
UserPublicKey::UserPublicKey() { g1_new(key_val); }
UserPublicKey::~UserPublicKey() { g1_free(key_val); }
UserPublicKey::UserPublicKey(const UserPublicKey& other) : UserPublicKey() { *this = other; }
UserPublicKey& UserPublicKey::operator=(const UserPublicKey& other) {
    if (this == &other) return *this;
    g1_copy(key_val, other.key_val);
    return *this;
}
std::string UserPublicKey::serialize() const { return g1_to_string_custom(key_val); }
void UserPublicKey::deserialize(const std::string& s) { string_to_g1_custom(key_val, s); }
bool UserPublicKey::operator==(const UserPublicKey& other) const { return g1_cmp(key_val, other.key_val) == RLC_EQ; }
bool UserPublicKey::operator<(const UserPublicKey& other) const { return serialize() < other.serialize(); }


// --- PartialPrivateKey ---
PartialPrivateKey::PartialPrivateKey() { g1_new(x0); g1_new(sL); }
PartialPrivateKey::~PartialPrivateKey() { g1_free(x0); g1_free(sL); }
PartialPrivateKey::PartialPrivateKey(const PartialPrivateKey& other) : PartialPrivateKey() { *this = other; }
PartialPrivateKey& PartialPrivateKey::operator=(const PartialPrivateKey& other) {
    if (this == &other) return *this;
    g1_copy(x0, other.x0); g1_copy(sL, other.sL);
    return *this;
}
std::string PartialPrivateKey::serialize() const {
    return g1_to_string_custom(x0) + "|" + g1_to_string_custom(sL);
}
void PartialPrivateKey::deserialize(const std::string& s) {
    std::stringstream ss(s);
    std::string item;
    std::getline(ss, item, '|'); string_to_g1_custom(x0, item);
    std::getline(ss, item, '|'); string_to_g1_custom(sL, item);
}

// --- UserSecretKey ---
UserSecretKey::UserSecretKey() { g1_new(x1); g1_new(sL); }
UserSecretKey::~UserSecretKey() { g1_free(x1); g1_free(sL); }
UserSecretKey::UserSecretKey(const UserSecretKey& other) : UserSecretKey() { *this = other; }
UserSecretKey& UserSecretKey::operator=(const UserSecretKey& other) {
    if (this == &other) return *this;
    g1_copy(x1, other.x1); g1_copy(sL, other.sL);
    return *this;
}

// --- Signature ---
Signature::Signature() {
    g1_new(sigma0); gt_new(sigma1); g1_new(sigma2); g1_new(sigma3); g1_new(sigma4);
}
Signature::~Signature() {
    g1_free(sigma0); gt_free(sigma1); g1_free(sigma2); g1_free(sigma3); g1_free(sigma4);
}
Signature::Signature(const Signature& other) : Signature() { *this = other; }
Signature& Signature::operator=(const Signature& other) {
    if (this == &other) return *this;
    g1_copy(sigma0, other.sigma0); gt_copy(sigma1, other.sigma1); g1_copy(sigma2, other.sigma2);
    g1_copy(sigma3, other.sigma3); g1_copy(sigma4, other.sigma4);
    return *this;
}
std::string Signature::serialize() const {
    std::string s;
    s += g1_to_string_custom(sigma0) + "|"; s += gt_to_string_custom(sigma1) + "|";
    s += g1_to_string_custom(sigma2) + "|"; s += g1_to_string_custom(sigma3) + "|";
    s += g1_to_string_custom(sigma4);
    return s;
}
void Signature::deserialize(const std::string& s) {
    std::stringstream ss(s);
    std::string item;
    std::getline(ss, item, '|'); string_to_g1_custom(sigma0, item);
    std::getline(ss, item, '|'); string_to_gt_custom(sigma1, item);
    std::getline(ss, item, '|'); string_to_g1_custom(sigma2, item);
    std::getline(ss, item, '|'); string_to_g1_custom(sigma3, item);
    std::getline(ss, item, '|'); string_to_g1_custom(sigma4, item);
}

#endif // TCRS_TYPES_H