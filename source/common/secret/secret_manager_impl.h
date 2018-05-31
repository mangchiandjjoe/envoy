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

private:
  void addOrUpdateSecret(const SecretSharedPtr& secret) override;
  const SecretSharedPtr findSecret(Secret::SecretType type, const std::string& name) const override;

  // manages pair of name and secret grouped by type of secret.
  std::unordered_map<Secret::SecretType, std::unordered_map<std::string, SecretSharedPtr>> secrets_;
};

} // namespace Secret
} // namespace Envoy
