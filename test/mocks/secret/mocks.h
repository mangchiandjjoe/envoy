#pragma once

#include "envoy/secret/secret_manager.h"
#include "envoy/ssl/tls_certificate_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

namespace Envoy {
namespace Secret {

class MockSecretManager : public SecretManager {
public:
  MockSecretManager();
  ~MockSecretManager();

  MOCK_METHOD2(addOrUpdateSecret, void(const std::string& config_source_hash,
                                       const envoy::api::v2::auth::Secret& secret));
  MOCK_CONST_METHOD2(findTlsCertificate,
                     Ssl::TlsCertificateConfigSharedPtr(const std::string& config_source_hash,
                                                        const std::string& name));
  MOCK_METHOD1(addOrUpdateSdsService,
               std::string(const envoy::api::v2::core::ConfigSource& config_source));
  MOCK_METHOD3(registerTlsCertificateConfigCallbacks,
               void(const std::string& config_source_hash, const std::string& secret_name,
                    SecretCallbacks& callback));
};

} // namespace Secret
  // namespace Secret
} // namespace Envoy
