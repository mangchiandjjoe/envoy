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

  const Protobuf::Message& message() const override { return message_; }

  const std::string& name() const override { return name_; }

  const std::string& certificateChain() const { return certificate_chain_; }
  const std::string& privateKey() const { return private_key_; }

private:
  const envoy::api::v2::auth::Secret message_;

  const std::string name_;
  const std::string certificate_chain_;
  const std::string private_key_;
};

} // namespace Ssl
} // namespace Envoy
