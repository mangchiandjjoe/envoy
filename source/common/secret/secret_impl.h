#pragma once

#include <string>
#include <unordered_map>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/secret/secret.h"

namespace Envoy {
namespace Secret {

class SecretImpl : public Secret {
public:
  SecretImpl(const envoy::api::v2::auth::Secret& config);
  const std::string& name() const override { return name_; }
  const std::string& certificateChain() const override { return certificate_chain_; }
  const std::string& privateKey() const override { return private_key_; }

private:
  const std::string name_;
  const std::string certificate_chain_;
  const std::string private_key_;
};

} // namespace Secret
} // namespace Envoy
