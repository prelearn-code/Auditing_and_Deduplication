#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace audit_dedupe {

struct GroupElement {
  std::uint64_t value{0};
};

struct GTElement {
  std::uint64_t value{0};
};

struct SystemParams {
  std::uint64_t prime{0};
  std::uint64_t g{0};
  std::uint64_t h{0};
  std::uint64_t gamma{0};
  std::uint64_t varpi{0};
  std::uint64_t v{0};
  std::size_t n{0};
  std::size_t s{0};
  std::vector<std::uint64_t> h_powers;
  std::vector<std::uint64_t> u;
};

struct MasterSecret {
  std::uint64_t g{0};
  std::uint64_t gamma{0};
};

struct UserSecret {
  std::uint64_t x_t{0};
  std::string ssk_t;
  std::uint64_t sk_id{0};
};

struct UserPublic {
  std::uint64_t pk_t{0};
  std::string spk_t;
};

struct FileMeta {
  std::uint64_t k_l{0};
  std::string k_c;
  std::string k_l_masked;
  std::string eta_l;
  std::uint64_t sk_f{0};
  std::uint64_t pk_f{0};
  std::uint64_t k_f{0};
  std::string c_l;
  std::vector<std::vector<std::uint64_t>> sectors;
  std::vector<std::uint64_t> sigmas;
};

struct IBBEHeader {
  std::uint64_t c_f1{0};
  std::uint64_t c_f2{0};
};

struct UploadPacket {
  std::string file_tag;
  std::string eta_l;
  std::string cipher_text;
  std::string k_l_masked;
  std::vector<std::uint64_t> sigmas;
  IBBEHeader header;
  std::string ck_f;
  std::string d_f;
  std::string tau_t;
  std::uint64_t pk_f{0};
  std::uint64_t k_f_t{0};
};

struct PoWChallenge {
  std::size_t c{0};
  std::uint64_t k1{0};
  std::uint64_t k2{0};
};

struct PoWProof {
  std::vector<std::uint64_t> mu;
};

struct AuditChallenge {
  std::size_t c{0};
  std::uint64_t k1{0};
  std::uint64_t k2{0};
};

struct AuditProof {
  std::vector<std::uint64_t> mu;
  std::uint64_t sigma{0};
};

struct BatchChallengeMultiFile {
  std::size_t c{0};
  std::uint64_t k1{0};
  std::uint64_t k2{0};
  std::uint64_t k3{0};
};

struct BatchProofMultiFile {
  std::vector<std::uint64_t> mu;
  std::uint64_t sigma{0};
};

struct BatchProofMultiUser {
  std::vector<std::uint64_t> mu;
  std::uint64_t sigma{0};
};

struct CSPState {
  std::unordered_map<std::string, UploadPacket> storage;
  std::unordered_map<std::string, std::vector<std::string>> sharing_list;
};

SystemParams SystemSetup(std::size_t n, std::size_t s, std::size_t m);

std::pair<UserSecret, UserPublic> UserSetup(const SystemParams& params,
                                            const MasterSecret& msk,
                                            const std::string& id_t);

UploadPacket InitialUpload(const SystemParams& params,
                           const UserSecret& user_sk,
                           const UserPublic& user_pk,
                           const std::string& id_t,
                           const std::string& file);

bool VerifyUpload(const SystemParams& params,
                  const UploadPacket& packet,
                  const UserPublic& user_pk);

PoWChallenge GeneratePoWChallenge(std::size_t c, std::uint64_t k1, std::uint64_t k2);

PoWProof GeneratePoWProof(const SystemParams& params,
                          const std::string& file,
                          const std::string& k_l_masked,
                          const PoWChallenge& chal);

bool VerifyPoW(const SystemParams& params,
               const UploadPacket& stored,
               const UserPublic& user_pk,
               const PoWProof& proof,
               const PoWChallenge& chal);

IBBEHeader UpdateIBBEHeader(const SystemParams& params,
                            const IBBEHeader& old_header,
                            const std::string& id_new);

AuditChallenge GenerateAuditChallenge(std::size_t c, std::uint64_t k1, std::uint64_t k2);

AuditProof GenerateAuditProof(const SystemParams& params,
                              const UploadPacket& stored,
                              const AuditChallenge& chal);

bool VerifyAudit(const SystemParams& params,
                 const UploadPacket& stored,
                 const UserPublic& user_pk,
                 const AuditProof& proof,
                 const AuditChallenge& chal,
                 std::uint64_t k_f_t);

BatchProofMultiFile GenerateBatchProofMultiFile(const SystemParams& params,
                                                const std::vector<UploadPacket>& packets,
                                                const BatchChallengeMultiFile& chal,
                                                const std::vector<std::uint64_t>& x_k);

bool VerifyBatchMultiFile(const SystemParams& params,
                          const std::vector<UploadPacket>& packets,
                          const UserPublic& user_pk,
                          const BatchProofMultiFile& proof,
                          const BatchChallengeMultiFile& chal,
                          const std::vector<std::uint64_t>& k_f_t,
                          const std::vector<std::uint64_t>& x_k);

BatchProofMultiUser GenerateBatchProofMultiUser(const SystemParams& params,
                                                const UploadPacket& packet,
                                                const BatchChallengeMultiFile& chal,
                                                std::size_t user_count);

bool VerifyBatchMultiUser(const SystemParams& params,
                          const UploadPacket& packet,
                          const std::vector<UserPublic>& users,
                          const BatchProofMultiUser& proof,
                          const BatchChallengeMultiFile& chal,
                          const std::vector<std::uint64_t>& k_f_t,
                          std::size_t user_count);

}  // namespace audit_dedupe
