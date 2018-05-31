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
  SecretType type() const { return SecretType::TLS_CERTIFICATE; }

  const std::string& certificateChain() const { return certificate_chain_; }
  const std::string& privateKey() const { return private_key_; }

private:
  const std::string name_;
  const std::string certificate_chain_;
  const std::string private_key_;
};

} // namespace Ssl
} // namespace Envoy
