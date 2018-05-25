#include "common/secret/secret_manager_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addOrUpdateStaticSecret(SecretSharedPtr secret) {
  static_secrets_[secret->name()] = secret;
}

const SecretSharedPtr SecretManagerImpl::findSecret(const std::string& name) const {
  auto static_secret = static_secrets_.find(name);
  return (static_secret != static_secrets_.end()) ? static_secret->second : nullptr;
}

} // namespace Secret
} // namespace Envoy
