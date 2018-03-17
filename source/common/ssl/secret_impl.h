#pragma once

#include "envoy/ssl/secret.h"

#include "envoy/api/v2/auth/cert.pb.h"

namespace Envoy {
namespace Ssl {

class SecretImpl : public Secret {
 public:
  SecretImpl(const std::string& certificate_chain,
             const std::string& private_key);

  virtual ~SecretImpl() {
  }

  const std::string getCertificateChain() override {
    return certificate_chain_;
  }

  const std::string getPrivateKey() override {
    return private_key_;
  }

 private:
  std::string name_;
  std::string certificate_chain_;
  std::string private_key_;
};

}  // namespace Upstream
}  // namespace Envoy
