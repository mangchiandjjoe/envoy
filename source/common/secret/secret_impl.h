#pragma once

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/secret/secret.h"

namespace Envoy {
namespace Secret {

typedef std::unordered_map<std::string, SecretSharedPtr> SecretSharedPtrMap;

class SecretImpl : public Secret {
public:
  SecretImpl(const envoy::api::v2::auth::Secret& config, const bool from_sds,
             const uint64_t config_source_hash);

  const std::string& name() const override { return name_; }
  const std::string& certificateChain() const override { return certificate_chain_; }
  const std::string& privateKey() const override { return private_key_; }
  bool fromSDS() const { return from_sds_; }
  uint64_t configSourceHash() const { return config_source_hash_; }

private:
  const std::string name_;
  const std::string certificate_chain_;
  const std::string private_key_;
  const bool from_sds_;
  const uint64_t config_source_hash_;
};

} // namespace Secret
} // namespace Envoy
