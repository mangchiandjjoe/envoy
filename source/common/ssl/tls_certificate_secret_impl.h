#pragma once

#include <string>
#include <unordered_map>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/secret/secret.h"

namespace Envoy {
namespace Ssl {

class TlsCertificateSecretImpl : public Secret::TlsCertificateSecret {
public:
  TlsCertificateSecretImpl(const std::string& name,
                           const envoy::api::v2::auth::TlsCertificate& config);

  const std::string& name() const override { return name_; }
  const std::string& certificateChain() const override { return certificate_chain_; }
  const std::string& privateKey() const override { return private_key_; }
  bool equalTo(const TlsCertificateSecret& secret) const override;

private:
  const std::string name_;
  const std::string certificate_chain_;
  const std::string private_key_;
};

} // namespace Ssl
} // namespace Envoy
