#include <memory>

#include "envoy/api/v2/auth/cert.pb.h"

#include "common/secret/secret_manager_impl.h"
#include "common/ssl/tls_certificate_config_impl.h"

#include "test/test_common/certs_test_expected.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {
namespace {

class SecretManagerImplTest : public testing::Test {};

TEST_F(SecretManagerImplTest, WeightedClusterFallthroughConfig) {
  envoy::api::v2::auth::Secret secret_config;

  secret_config.set_name("abc.com");
  auto tls_certificate = secret_config.mutable_tls_certificate();
  tls_certificate->mutable_certificate_chain()->set_filename(
      "test/common/ssl/test_data/selfsigned_cert.pem");
  tls_certificate->mutable_private_key()->set_filename(
      "test/common/ssl/test_data/selfsigned_key.pem");

  std::unique_ptr<SecretManager> secret_manager(new SecretManagerImpl());

  secret_manager->addOrUpdateSecret(std::make_shared<Ssl::TlsCertificateConfigImpl>(secret_config));

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

} // namespace
} // namespace Secret
} // namespace Envoy
