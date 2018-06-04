#include <memory>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/common/exception.h"

#include "common/secret/secret_manager_impl.h"
#include "common/ssl/tls_certificate_config_impl.h"

#include "test/test_common/certs_test_expected.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {
namespace {

class SecretManagerImplTest : public testing::Test {};

TEST_F(SecretManagerImplTest, SecretLoadSuccess) {
  envoy::api::v2::auth::Secret secret_config;

  std::string yaml = R"EOF(
name: "abc.com"
tls_certificate:
  certificate_chain:
    filename: "test/common/ssl/test_data/selfsigned_cert.pem"
  private_key:
    filename: "test/common/ssl/test_data/selfsigned_key.pem"
)EOF";

  MessageUtil::loadFromYaml(yaml, secret_config);

  std::unique_ptr<SecretManager> secret_manager(new SecretManagerImpl());

  secret_manager->addOrUpdateSecret(secret_config);

  ASSERT_EQ(secret_manager->findSecret(Secret::SecretType::TLS_CERTIFICATE, "undefined"), nullptr);

  ASSERT_NE(secret_manager->findSecret(Secret::SecretType::TLS_CERTIFICATE, "abc.com"), nullptr);

  EXPECT_EQ(Testdata::kExpectedCertificateChain,
            std::dynamic_pointer_cast<Ssl::TlsCertificateConfigImpl>(
                secret_manager->findSecret(Secret::SecretType::TLS_CERTIFICATE, "abc.com"))
                ->certificateChain());

  EXPECT_EQ(Testdata::kExpectedPrivateKey,
            std::dynamic_pointer_cast<Ssl::TlsCertificateConfigImpl>(
                secret_manager->findSecret(Secret::SecretType::TLS_CERTIFICATE, "abc.com"))
                ->privateKey());
}

TEST_F(SecretManagerImplTest, NotImplementedException) {
  envoy::api::v2::auth::Secret secret_config;

  std::string yaml = R"EOF(
name: "abc.com"
session_ticket_keys:
  keys:
    - filename: "test/common/ssl/test_data/selfsigned_cert.pem"
)EOF";

  MessageUtil::loadFromYaml(yaml, secret_config);

  std::unique_ptr<SecretManager> secret_manager(new SecretManagerImpl());

  EXPECT_THROW_WITH_MESSAGE(secret_manager->addOrUpdateSecret(secret_config), EnvoyException,
                            "Secret type not implemented");
}

} // namespace
} // namespace Secret
} // namespace Envoy
