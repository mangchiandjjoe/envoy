#pragma once

#include <unordered_map>

#include "envoy/secret/secret.h"
#include "envoy/secret/secret_manager.h"

#include "common/common/logger.h"

namespace Envoy {
namespace Secret {

class SecretManagerImpl : public SecretManager, Logger::Loggable<Logger::Id::upstream> {
public:
  SecretManagerImpl(){};

  void addOrUpdateSecret(SecretSharedPtr secret) override;
  const SecretSharedPtr findSecret(const std::string& name) const override;

private:
  typedef std::unordered_map<std::string, SecretSharedPtr> SecretSharedPtrMap;

  SecretSharedPtrMap static_secrets_;
};

} // namespace Secret
} // namespace Envoy
