#pragma once

#include <string>
#include <unordered_map>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/secret/secret.h"

namespace Envoy {
namespace Ssl {

class TlsCertificateConfigImpl : public Secret::Secret {
public:
  TlsCertificateConfigImpl(const envoy::api::v2::auth::Secret& config);

  const std::string& name() const override { return name_; }
  SecretType type() const override { return type_; }

  bool equalTo(const Envoy::Secret::SecretSharedPtr& secret) const override;

  const std::string& certificateChain() const { return certificate_chain_; }

  const std::string& privateKey() const { return private_key_; }

private:
  const envoy::api::v2::auth::Secret message_;

  const std::string name_;
  const std::string certificate_chain_;
  const std::string private_key_;
  const std::string config_source_;
  const Secret::SecretType type_;
};

} // namespace Ssl
} // namespace Envoy
