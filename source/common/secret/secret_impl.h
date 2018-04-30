#pragma once

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/secret/secret.h"
#include "common/common/logger.h"

namespace Envoy {
namespace Secret {

class SecretImpl : public Secret, Logger::Loggable<Logger::Id::upstream> {
 public:
  SecretImpl(const envoy::api::v2::auth::Secret& config, bool is_static);

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
  const std::string readDataSource(const envoy::api::v2::core::DataSource& source,
                                   bool allow_empty);
  const std::string getDataSourcePath(const envoy::api::v2::core::DataSource& source);

 private:
  std::string name_;
  std::string certificate_chain_;
  std::string private_key_;
  bool is_static_;
};

}  // namespace Secret
}  // namespace Envoy
