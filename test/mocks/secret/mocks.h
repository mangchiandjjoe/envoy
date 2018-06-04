#pragma once

#include <chrono>
#include <cstdint>
#include <list>
#include <string>

#include "envoy/secret/secret.h"
#include "envoy/secret/secret_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {

class MockSecretManager : public SecretManager {
public:
  MockSecretManager();
  ~MockSecretManager();

  MOCK_METHOD1(addOrUpdateSecret, void(const SecretSharedPtr& secret));
  MOCK_CONST_METHOD2(findSecret,
                     const SecretSharedPtr(Secret::SecretType type, const std::string& name));
  MOCK_CONST_METHOD1(loadSecret, const SecretSharedPtr(const envoy::api::v2::auth::Secret& secret));
};

} // namespace Secret
} // namespace Envoy
