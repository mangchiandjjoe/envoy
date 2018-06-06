#pragma once

#include "test/mocks/server/mocks.h"
#include "test/test_common/environment.h"

#include "gtest/gtest.h"

namespace Envoy {
class SslCertsTest : public testing::Test {
 public:
  SslCertsTest()
      : secret_manager_(new Secret::SecretManagerImpl(this->server)) {
  }

  static void SetUpTestCase() {
    TestEnvironment::exec({TestEnvironment::runfilesPath("test/common/ssl/gen_unittest_certs.sh")});
  }

  Server::MockInstance server;
  std::unique_ptr<Secret::SecretManager> secret_manager_;
};
}  // namespace Envoy
