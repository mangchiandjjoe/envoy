#include <memory>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/common/exception.h"

#include "common/event/dispatcher_impl.h"
#include "common/secret/secret_manager_impl.h"
#include "common/ssl/tls_certificate_config_impl.h"

#include "test/mocks/server/mocks.h"
#include "test/test_common/certs_test_expected.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {
namespace {

class MockServer : public Server::MockInstance {
public:
  Event::Dispatcher& dispatcher() override { return dispatcher_; }
  Init::Manager& initManager() { return initmanager_; }

private:
  Event::DispatcherImpl dispatcher_;

  class InitManager : public Init::Manager {
  public:
    void initialize(std::function<void()> callback);
    void registerTarget(Init::Target&) override {}
  };

  InitManager initmanager_;
};

class MockSecretCallback : public SecretCallbacks {
public:
  MOCK_METHOD0(onAddOrUpdateSecret, void());
};

class SecretManagerImplTest : public testing::Test {};

TEST_F(SecretManagerImplTest, SdsStaticSecret) {
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

  Server::MockInstance server;

  server.secretManager().addOrUpdateSecret("", secret_config);

  ASSERT_EQ(server.secretManager().findSecret(Secret::SecretType::TLS_CERTIFICATE, "", "undefined"),
            nullptr);

  ASSERT_NE(server.secretManager().findSecret(Secret::SecretType::TLS_CERTIFICATE, "", "abc.com"),
            nullptr);

  EXPECT_EQ(
      Testdata::kExpectedCertificateChain,
      std::dynamic_pointer_cast<Ssl::TlsCertificateConfigImpl>(
          server.secretManager().findSecret(Secret::SecretType::TLS_CERTIFICATE, "", "abc.com"))
          ->certificateChain());

  EXPECT_EQ(
      Testdata::kExpectedPrivateKey,
      std::dynamic_pointer_cast<Ssl::TlsCertificateConfigImpl>(
          server.secretManager().findSecret(Secret::SecretType::TLS_CERTIFICATE, "", "abc.com"))
          ->privateKey());
}

TEST_F(SecretManagerImplTest, SdsDynamicSecretCallback) {
  envoy::api::v2::core::ConfigSource config_source;
  envoy::api::v2::auth::Secret secret_config;

  std::string yaml =
      R"EOF(
name: "abc.com"
tls_certificate:
  certificate_chain:
    filename: "test/common/ssl/test_data/selfsigned_cert.pem"
  private_key:
    filename: "test/common/ssl/test_data/selfsigned_key.pem"
)EOF";

  MessageUtil::loadFromYaml(yaml, secret_config);

  MockServer server;

  std::unique_ptr<MockSecretCallback> secret_callback(
      new ::testing::NiceMock<MockSecretCallback>());
  EXPECT_CALL(*secret_callback.get(), onAddOrUpdateSecret());
  std::string config_source_hash = server.secretManager().addOrUpdateSdsService(config_source);

  server.secretManager().registerSecretCallbacks(config_source_hash, "abc.com",
                                                 *secret_callback.get());
  server.secretManager().addOrUpdateSecret(config_source_hash, secret_config);

  server.dispatcher().run(Event::Dispatcher::RunType::Block);

  ASSERT_EQ(server.secretManager().findSecret(Secret::SecretType::TLS_CERTIFICATE,
                                              config_source_hash, "undefined"),
            nullptr);

  EXPECT_EQ(Testdata::kExpectedCertificateChain,
            std::dynamic_pointer_cast<Ssl::TlsCertificateConfigImpl>(
                server.secretManager().findSecret(Secret::SecretType::TLS_CERTIFICATE,
                                                  config_source_hash, "abc.com"))
                ->certificateChain());

  EXPECT_EQ(Testdata::kExpectedPrivateKey,
            std::dynamic_pointer_cast<Ssl::TlsCertificateConfigImpl>(
                server.secretManager().findSecret(Secret::SecretType::TLS_CERTIFICATE,
                                                  config_source_hash, "abc.com"))
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

  Server::MockInstance server;
  std::unique_ptr<SecretManager> secret_manager(new SecretManagerImpl(server));

  EXPECT_THROW_WITH_MESSAGE(secret_manager->addOrUpdateSecret("", secret_config), EnvoyException,
                            "Secret type not implemented");
}

} // namespace
} // namespace Secret
} // namespace Envoy
