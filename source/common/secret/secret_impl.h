#pragma once

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/secret/secret.h"

namespace Envoy {
namespace Secret {

typedef std::unordered_map<std::string, SecretSharedPtr> SecretSharedPtrMap;

class SecretImpl : public Secret {
public:
  SecretImpl(const envoy::api::v2::auth::Secret& config);

  const std::string& name() override { return name_; }

  const std::string& certificateChain() override { return certificate_chain_; }

  const std::string& privateKey() override { return private_key_; }

private:
  const std::string name_;
  const std::string certificate_chain_;
  const std::string private_key_;
};

} // namespace Secret
} // namespace Envoy
