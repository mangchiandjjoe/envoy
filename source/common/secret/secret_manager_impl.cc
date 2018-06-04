#include "common/secret/secret_manager_impl.h"

#include "envoy/common/exception.h"

#include "common/ssl/tls_certificate_config_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addOrUpdateSecret(const SecretSharedPtr& secret) {
  secrets_[secret->type()][secret->name()] = secret;
}

const SecretSharedPtr SecretManagerImpl::findSecret(Secret::SecretType type,
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

const SecretSharedPtr
SecretManagerImpl::loadSecret(const envoy::api::v2::auth::Secret& secret) const {

  switch (secret.type_case()) {
  case envoy::api::v2::auth::Secret::TypeCase::kTlsCertificate:
    return std::make_shared<Ssl::TlsCertificateConfigImpl>(secret);
  default:
    throw EnvoyException("Secret type not implemented");
  }
}

} // namespace Secret
} // namespace Envoy
