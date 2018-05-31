#include "common/secret/secret_manager_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addOrUpdateSecret(const std::string& type, const SecretSharedPtr& secret) {
  auto type_secrets = secrets_.find(type);
  if (type_secrets == secrets_.end()) {
    secrets_[type] = {};
    type_secrets = secrets_.find(type);
  }

  type_secrets->second[secret->name()] = secret;
}

const SecretSharedPtr SecretManagerImpl::findSecret(const std::string& type,
                                                    const std::string& name) const {
  auto type_secrets = secrets_.find(type);
  if (type_secrets == secrets_.end()) {
    return nullptr;
  }

  auto secret = type_secrets->second.find(name);
  if (secret == type_secrets->second.end()) {
    return nullptr;
  }

  return secret->second;
}

} // namespace Secret
} // namespace Envoy
