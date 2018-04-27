#pragma once

#include <envoy/secret/secret.h>
#include "envoy/api/v2/auth/cert.pb.h"

namespace Envoy {
namespace Ssl {

class SecretImpl : public Secret {
 public:
  SecretImpl(const std::string& certificate_chain,
             const std::string& private_key, bool is_static);

  SecretImpl(const std::string& certificate_chain,
             const std::string& private_key)
      : SecretImpl(certificate_chain, private_key, false) {

  }

  virtual ~SecretImpl() {
  }

  const std::string getCertificateChain() override {
    return certificate_chain_;
  }

  const std::string getPrivateKey() override {
    return private_key_;
  }

  bool isStatic() override {
    return is_static_;
  }

 private:
  std::string name_;
  std::string certificate_chain_;
  std::string private_key_;
  bool is_static_;
};

}  // namespace Upstream
}  // namespace Envoy
