#include "scheme.hpp"

#include <random>
#include <sstream>

namespace audit_dedupe {

namespace {

constexpr std::uint64_t kPrime = 2147483647ULL;

std::uint64_t ModAdd(std::uint64_t a, std::uint64_t b, std::uint64_t mod = kPrime) {
  return (a % mod + b % mod) % mod;
}

std::uint64_t ModMul(std::uint64_t a, std::uint64_t b, std::uint64_t mod = kPrime) {
  return (a % mod * b % mod) % mod;
}

std::uint64_t ModPow(std::uint64_t base, std::uint64_t exp, std::uint64_t mod = kPrime) {
  std::uint64_t result = 1 % mod;
  base %= mod;
  while (exp > 0) {
    if (exp & 1ULL) {
      result = ModMul(result, base, mod);
    }
    base = ModMul(base, base, mod);
    exp >>= 1ULL;
  }
  return result;
}

std::uint64_t HashToZq(const std::string& input, std::uint64_t mod = kPrime) {
  std::uint64_t hash = 0;
  for (unsigned char c : input) {
    hash = (hash * 131 + c) % mod;
  }
  return (hash == 0) ? 1 : hash;
}

std::uint64_t HashToZqWithLabel(const std::string& label, const std::string& input) {
  return HashToZq(label + "::" + input, kPrime);
}

std::uint64_t HashToGroup(const std::string& input) {
  return HashToZqWithLabel("H4", input);
}

std::string XorMask(const std::string& data, const std::string& key) {
  if (key.empty()) {
    return data;
  }
  std::string masked = data;
  for (std::size_t i = 0; i < data.size(); ++i) {
    masked[i] = static_cast<char>(data[i] ^ key[i % key.size()]);
  }
  return masked;
}

std::string SymmetricEncrypt(const std::string& key, const std::string& data) {
  return XorMask(data, key);
}

std::string SymmetricDecrypt(const std::string& key, const std::string& data) {
  return XorMask(data, key);
}

std::vector<std::vector<std::uint64_t>> SplitToSectors(const std::string& data,
                                                       std::size_t n,
                                                       std::size_t s) {
  std::vector<std::vector<std::uint64_t>> sectors;
  sectors.resize(n, std::vector<std::uint64_t>(s, 0));
  std::size_t idx = 0;
  for (std::size_t i = 0; i < n; ++i) {
    for (std::size_t j = 0; j < s; ++j) {
      std::string token(1, data[idx % data.size()]);
      sectors[i][j] = HashToZq(token);
      ++idx;
    }
  }
  return sectors;
}

std::vector<std::size_t> GenerateIndices(std::size_t n, std::size_t c, std::uint64_t seed) {
  std::mt19937_64 prng(seed);
  std::vector<std::size_t> indices;
  indices.reserve(c);
  for (std::size_t i = 0; i < c; ++i) {
    indices.push_back(prng() % n);
  }
  return indices;
}

std::vector<std::uint64_t> GenerateCoefficients(std::size_t c, std::uint64_t seed) {
  std::mt19937_64 prng(seed);
  std::vector<std::uint64_t> coeffs;
  coeffs.reserve(c);
  for (std::size_t i = 0; i < c; ++i) {
    coeffs.push_back((prng() % (kPrime - 1)) + 1);
  }
  return coeffs;
}

std::string ToHex(std::uint64_t value) {
  std::ostringstream oss;
  oss << std::hex << value;
  return oss.str();
}

std::uint64_t Pairing(std::uint64_t a, std::uint64_t b) {
  return ModMul(a, b);
}

}  // namespace

SystemParams SystemSetup(std::size_t n, std::size_t s, std::size_t m) {
  SystemParams params;
  params.prime = kPrime;
  params.n = n;
  params.s = s;
  params.g = 5;
  params.h = 7;
  params.gamma = 19;
  params.varpi = ModPow(params.g, params.gamma);
  params.v = Pairing(params.g, params.h);
  params.h_powers.reserve(m + 1);
  std::uint64_t gamma_pow = 1;
  for (std::size_t i = 0; i <= m; ++i) {
    params.h_powers.push_back(ModPow(params.h, gamma_pow));
    gamma_pow = ModMul(gamma_pow, params.gamma);
  }
  params.u.reserve(s);
  for (std::size_t i = 0; i < s; ++i) {
    std::uint64_t a_k = 11 + static_cast<std::uint64_t>(i * 3);
    params.u.push_back(ModPow(params.g, a_k));
  }
  return params;
}

std::pair<UserSecret, UserPublic> UserSetup(const SystemParams& params,
                                            const MasterSecret& msk,
                                            const std::string& id_t) {
  UserSecret sk;
  UserPublic pk;
  sk.x_t = HashToZqWithLabel("x", id_t);
  sk.ssk_t = "ssk_" + id_t;
  std::uint64_t denom = ModAdd(msk.gamma, HashToZqWithLabel("H1", id_t));
  std::uint64_t inv = ModPow(denom, params.prime - 2);
  sk.sk_id = ModPow(msk.g, inv);
  pk.pk_t = ModPow(msk.g, sk.x_t);
  pk.spk_t = "spk_" + id_t;
  return {sk, pk};
}

UploadPacket InitialUpload(const SystemParams& params,
                           const UserSecret& user_sk,
                           const UserPublic& user_pk,
                           const std::string& id_t,
                           const std::string& file) {
  UploadPacket packet;
  std::string k_c = ToHex(HashToZqWithLabel("H2", file));
  std::string cipher_for_tag = SymmetricEncrypt(k_c, file);
  packet.file_tag = ToHex(HashToZqWithLabel("H1", cipher_for_tag));

  std::uint64_t k_l = HashToZqWithLabel("k_l", file + id_t);
  packet.cipher_text = SymmetricEncrypt(ToHex(k_l), file);
  packet.k_l_masked = XorMask(ToHex(k_l), k_c);
  packet.k_f_t = ModPow(params.g, user_sk.x_t);

  std::string eta_l = ToHex(HashToZqWithLabel("eta", packet.k_l_masked));
  packet.eta_l = eta_l;
  std::uint64_t sk_f = HashToZqWithLabel("H3", ToHex(k_l));
  std::uint64_t pk_f = ModPow(params.g, ModPow(sk_f, params.prime - 2));
  std::uint64_t k_f_t = ModPow(pk_f, user_sk.x_t);

  packet.pk_f = pk_f;
  packet.k_f_t = k_f_t;

  auto sectors = SplitToSectors(packet.cipher_text, params.n, params.s);
  packet.sigmas.resize(params.n);
  for (std::size_t i = 0; i < params.n; ++i) {
    std::uint64_t base = HashToGroup(eta_l + "|" + std::to_string(i + 1));
    std::uint64_t product = base;
    for (std::size_t j = 0; j < params.s; ++j) {
      std::uint64_t term = ModPow(params.u[j], sectors[i][j]);
      product = ModMul(product, term);
    }
    packet.sigmas[i] = ModPow(product, sk_f);
  }

  std::uint64_t k_f = HashToZqWithLabel("k_f", file + id_t + "header");
  std::uint64_t c_f1 = ModPow(params.varpi, params.prime - 1 - (k_f % (params.prime - 1)));
  std::uint64_t c_f2_base = ModMul(ModPow(params.h, params.gamma),
                                   ModPow(params.h, HashToZqWithLabel("H1", id_t)));
  std::uint64_t c_f2 = ModPow(c_f2_base, k_f);
  packet.header = {c_f1, c_f2};
  std::string k_ibf = ToHex(ModPow(params.v, k_f));
  packet.ck_f = SymmetricEncrypt(k_ibf, k_c);
  packet.d_f = SymmetricEncrypt(k_c, ToHex(k_f));

  std::string tau_0 = packet.file_tag + "|" + packet.k_l_masked + "|" + id_t;
  packet.tau_t = tau_0 + "|SSig(" + user_pk.spk_t + ")";
  return packet;
}

bool VerifyUpload(const SystemParams& params,
                  const UploadPacket& packet,
                  const UserPublic& user_pk) {
  std::uint64_t lhs = 1;
  for (auto sigma : packet.sigmas) {
    lhs = ModMul(lhs, sigma);
  }
  std::uint64_t left = Pairing(lhs, packet.k_f_t);

  std::uint64_t right_product = 1;
  for (std::size_t i = 0; i < packet.sigmas.size(); ++i) {
    std::uint64_t base = HashToGroup(packet.eta_l + "|" + std::to_string(i + 1));
    right_product = ModMul(right_product, base);
  }
  std::uint64_t right = Pairing(right_product, user_pk.pk_t);
  return left == right;
}

PoWChallenge GeneratePoWChallenge(std::size_t c, std::uint64_t k1, std::uint64_t k2) {
  return {c, k1, k2};
}

PoWProof GeneratePoWProof(const SystemParams& params,
                          const std::string& file,
                          const std::string& k_l_masked,
                          const PoWChallenge& chal) {
  PoWProof proof;
  std::string k_c = ToHex(HashToZqWithLabel("H2", file));
  std::string k_l_hex = XorMask(k_l_masked, k_c);
  std::string cipher = SymmetricEncrypt(k_l_hex, file);
  auto sectors = SplitToSectors(cipher, params.n, params.s);
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  proof.mu.assign(params.s, 0);
  for (std::size_t j = 0; j < params.s; ++j) {
    std::uint64_t sum = 0;
    for (std::size_t idx = 0; idx < indices.size(); ++idx) {
      std::size_t block = indices[idx];
      sum = ModAdd(sum, ModMul(coeffs[idx], sectors[block][j]));
    }
    proof.mu[j] = sum;
  }
  return proof;
}

bool VerifyPoW(const SystemParams& params,
               const UploadPacket& stored,
               const UserPublic& user_pk,
               const PoWProof& proof,
               const PoWChallenge& chal) {
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  std::uint64_t sigma = 1;
  for (std::size_t i = 0; i < indices.size(); ++i) {
    sigma = ModMul(sigma, ModPow(stored.sigmas[indices[i]], coeffs[i]));
  }
  std::uint64_t left = Pairing(sigma, stored.k_f_t);

  std::uint64_t right_factor = 1;
  for (std::size_t i = 0; i < indices.size(); ++i) {
    std::uint64_t base = HashToGroup(stored.eta_l + "|" + std::to_string(indices[i] + 1));
    right_factor = ModMul(right_factor, ModPow(base, coeffs[i]));
  }
  std::uint64_t sector_factor = 1;
  for (std::size_t j = 0; j < params.s; ++j) {
    sector_factor = ModMul(sector_factor, ModPow(params.u[j], proof.mu[j]));
  }
  std::uint64_t right = Pairing(ModMul(right_factor, sector_factor), user_pk.pk_t);
  return left == right;
}

IBBEHeader UpdateIBBEHeader(const SystemParams& params,
                            const IBBEHeader& old_header,
                            const std::string& id_new) {
  std::uint64_t exponent = ModAdd(params.gamma, HashToZqWithLabel("H1", id_new));
  std::uint64_t c_new = ModPow(old_header.c_f2, exponent);
  return {old_header.c_f1, c_new};
}

AuditChallenge GenerateAuditChallenge(std::size_t c, std::uint64_t k1, std::uint64_t k2) {
  return {c, k1, k2};
}

AuditProof GenerateAuditProof(const SystemParams& params,
                              const UploadPacket& stored,
                              const AuditChallenge& chal) {
  AuditProof proof;
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  proof.mu.assign(params.s, 0);
  for (std::size_t j = 0; j < params.s; ++j) {
    std::uint64_t sum = 0;
    for (std::size_t idx = 0; idx < indices.size(); ++idx) {
      sum = ModAdd(sum, ModMul(coeffs[idx], HashToZq("c" + std::to_string(indices[idx]) + ":" + std::to_string(j))));
    }
    proof.mu[j] = sum;
  }
  proof.sigma = 1;
  for (std::size_t idx = 0; idx < indices.size(); ++idx) {
    proof.sigma = ModMul(proof.sigma, ModPow(stored.sigmas[indices[idx]], coeffs[idx]));
  }
  return proof;
}

bool VerifyAudit(const SystemParams& params,
                 const UploadPacket& stored,
                 const UserPublic& user_pk,
                 const AuditProof& proof,
                 const AuditChallenge& chal,
                 std::uint64_t k_f_t) {
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  std::uint64_t left = Pairing(proof.sigma, k_f_t);
  std::uint64_t right_factor = 1;
  for (std::size_t i = 0; i < indices.size(); ++i) {
    std::uint64_t base = HashToGroup(stored.eta_l + "|" + std::to_string(indices[i] + 1));
    right_factor = ModMul(right_factor, ModPow(base, coeffs[i]));
  }
  std::uint64_t sector_factor = 1;
  for (std::size_t j = 0; j < params.s; ++j) {
    sector_factor = ModMul(sector_factor, ModPow(params.u[j], proof.mu[j]));
  }
  std::uint64_t right = Pairing(ModMul(right_factor, sector_factor), user_pk.pk_t);
  return left == right;
}

BatchProofMultiFile GenerateBatchProofMultiFile(const SystemParams& params,
                                                const std::vector<UploadPacket>& packets,
                                                const BatchChallengeMultiFile& chal,
                                                const std::vector<std::uint64_t>& x_k) {
  BatchProofMultiFile proof;
  proof.mu.assign(params.s, 0);
  std::uint64_t sigma = 1;
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  for (std::size_t file_idx = 0; file_idx < packets.size(); ++file_idx) {
    std::uint64_t sigma_file = 1;
    for (std::size_t i = 0; i < indices.size(); ++i) {
      sigma_file = ModMul(sigma_file, ModPow(packets[file_idx].sigmas[indices[i]], coeffs[i]));
    }
    sigma = ModMul(sigma, ModPow(sigma_file, x_k[file_idx]));
    for (std::size_t j = 0; j < params.s; ++j) {
      std::uint64_t sum = 0;
      for (std::size_t i = 0; i < indices.size(); ++i) {
        sum = ModAdd(sum, ModMul(coeffs[i], HashToZq("f" + std::to_string(file_idx) + ":" + std::to_string(indices[i]) + ":" + std::to_string(j))));
      }
      proof.mu[j] = ModAdd(proof.mu[j], ModMul(x_k[file_idx], sum));
    }
  }
  proof.sigma = sigma;
  return proof;
}

bool VerifyBatchMultiFile(const SystemParams& params,
                          const std::vector<UploadPacket>& packets,
                          const UserPublic& user_pk,
                          const BatchProofMultiFile& proof,
                          const BatchChallengeMultiFile& chal,
                          const std::vector<std::uint64_t>& k_f_t,
                          const std::vector<std::uint64_t>& x_k) {
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  std::uint64_t k_f_prod = 1;
  for (auto key : k_f_t) {
    k_f_prod = ModMul(k_f_prod, key);
  }
  std::uint64_t left = Pairing(proof.sigma, k_f_prod);
  std::uint64_t right_factor = 1;
  for (std::size_t file_idx = 0; file_idx < packets.size(); ++file_idx) {
    for (std::size_t i = 0; i < indices.size(); ++i) {
      std::uint64_t base = HashToGroup(packets[file_idx].eta_l + "|" + std::to_string(indices[i] + 1));
      right_factor = ModMul(right_factor, ModPow(base, ModMul(x_k[file_idx], coeffs[i])));
    }
  }
  std::uint64_t sector_factor = 1;
  for (std::size_t j = 0; j < params.s; ++j) {
    sector_factor = ModMul(sector_factor, ModPow(params.u[j], proof.mu[j]));
  }
  std::uint64_t right = Pairing(ModMul(right_factor, sector_factor), user_pk.pk_t);
  return left == right;
}

BatchProofMultiUser GenerateBatchProofMultiUser(const SystemParams& params,
                                                const UploadPacket& packet,
                                                const BatchChallengeMultiFile& chal,
                                                std::size_t user_count) {
  BatchProofMultiUser proof;
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  proof.mu.assign(params.s, 0);
  for (std::size_t j = 0; j < params.s; ++j) {
    std::uint64_t sum = 0;
    for (std::size_t i = 0; i < indices.size(); ++i) {
      sum = ModAdd(sum, ModMul(coeffs[i] * user_count, HashToZq("shared:" + std::to_string(indices[i]) + ":" + std::to_string(j))));
    }
    proof.mu[j] = sum;
  }
  std::uint64_t sigma = 1;
  for (std::size_t i = 0; i < indices.size(); ++i) {
    sigma = ModMul(sigma, ModPow(packet.sigmas[indices[i]], coeffs[i]));
  }
  proof.sigma = ModPow(sigma, user_count);
  return proof;
}

bool VerifyBatchMultiUser(const SystemParams& params,
                          const UploadPacket& packet,
                          const std::vector<UserPublic>& users,
                          const BatchProofMultiUser& proof,
                          const BatchChallengeMultiFile& chal,
                          const std::vector<std::uint64_t>& k_f_t,
                          std::size_t user_count) {
  auto indices = GenerateIndices(params.n, chal.c, chal.k1);
  auto coeffs = GenerateCoefficients(chal.c, chal.k2);
  std::uint64_t k_f_prod = 1;
  for (auto key : k_f_t) {
    k_f_prod = ModMul(k_f_prod, key);
  }
  std::uint64_t left = Pairing(proof.sigma, k_f_prod);
  std::uint64_t right_factor = 1;
  for (std::size_t i = 0; i < indices.size(); ++i) {
    std::uint64_t base = HashToGroup(packet.eta_l + "|" + std::to_string(indices[i] + 1));
    right_factor = ModMul(right_factor, ModPow(base, coeffs[i] * user_count));
  }
  std::uint64_t sector_factor = 1;
  for (std::size_t j = 0; j < params.s; ++j) {
    sector_factor = ModMul(sector_factor, ModPow(params.u[j], proof.mu[j]));
  }
  std::uint64_t agg_pk = 1;
  for (const auto& user : users) {
    agg_pk = ModMul(agg_pk, user.pk_t);
  }
  std::uint64_t right = Pairing(ModMul(right_factor, sector_factor), agg_pk);
  return left == right;
}

}  // namespace audit_dedupe
