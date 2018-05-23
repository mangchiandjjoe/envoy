#pragma once

#include <unordered_map>

#include "envoy/secret/secret.h"
#include "envoy/secret/secret_manager.h"

#include "common/common/logger.h"

namespace Envoy {
namespace Secret {

typedef std::unordered_map<std::string, SecretSharedPtr> SecretSharedPtrMap;

class SecretManagerImpl : public SecretManager, Logger::Loggable<Logger::Id::upstream> {
public:
  SecretManagerImpl(){};

  void addOrUpdateStaticSecret(const SecretSharedPtr secret) override;
  const SecretSharedPtr staticSecret(const std::string& name) const override;

private:
  SecretSharedPtrMap static_secrets_;
};

} // namespace Secret
} // namespace Envoy
