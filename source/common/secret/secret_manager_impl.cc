#include "common/secret/secret_manager_impl.h"

#include "common/secret/secret_manager_util.h"
#include "common/ssl/tls_certificate_secret_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addOrUpdateSecret(const std::string& sds_config_source_hash,
                                          const envoy::api::v2::auth::Secret& secret_config) {
  switch (secret_config.type_case()) {
  case envoy::api::v2::auth::Secret::TypeCase::kTlsCertificate: {
    std::unique_lock<std::shared_timed_mutex> lhs(tls_certificate_secrets_mutex_);
    auto secret = std::make_shared<Ssl::TlsCertificateSecretImpl>(secret_config.name(),
                                                                  secret_config.tls_certificate());
    tls_certificate_secrets_[sds_config_source_hash][secret_config.name()] = secret;

    if (!sds_config_source_hash.empty()) {
      server_.dispatcher().post([this, &sds_config_source_hash, secret]() {
        std::shared_lock<std::shared_timed_mutex> lhs(
            tls_certificate_secret_update_callbacks_mutex_);
        auto config_source_it =
            tls_certificate_secret_update_callbacks_.find(sds_config_source_hash);
        if (config_source_it != tls_certificate_secret_update_callbacks_.end()) {
          auto callback_it = config_source_it->second.find(secret->name());
          if (callback_it != config_source_it->second.end()) {
            if (callback_it->second.first == nullptr ||
                !callback_it->second.first->equalTo(*secret.get())) {
              for (auto& callback : callback_it->second.second) {
                callback->onAddOrUpdateSecret();
              }
              callback_it->second.first = secret;
            }
          }
        }
      });
    }
  } break;
  default:
    throw EnvoyException("Secret type not implemented");
  }
}

const TlsCertificateSecretSharedPtr
SecretManagerImpl::findTlsCertificateSecret(const std::string& sds_config_source_hash,
                                            const std::string& name) const {
  std::shared_lock<std::shared_timed_mutex> lhs(tls_certificate_secrets_mutex_);

  auto config_source_it = tls_certificate_secrets_.find(sds_config_source_hash);
  if (config_source_it == tls_certificate_secrets_.end()) {
    return nullptr;
  }

  auto name_it = config_source_it->second.find(name);
  if (name_it == config_source_it->second.end()) {
    return nullptr;
  }

  return name_it->second;
}

std::string SecretManagerImpl::addOrUpdateSdsService(
    const envoy::api::v2::core::ConfigSource& sdsConfigSource) {
  std::unique_lock<std::shared_timed_mutex> lhs(sds_api_mutex_);

  auto hash = SecretManagerUtil::configSourceHash(sdsConfigSource);
  if (sds_apis_.find(hash) != sds_apis_.end()) {
    return hash;
  }

  sds_apis_[hash] = std::move(std::make_unique<SdsApi>(server_, sdsConfigSource));

  return hash;
}

void SecretManagerImpl::registerTlsCertificateSecretCallbacks(const std::string config_source_hash,
                                                              const std::string secret_name,
                                                              SecretCallbacks& callback) {
  auto secret = findTlsCertificateSecret(config_source_hash, secret_name);

  std::unique_lock<std::shared_timed_mutex> lhs(tls_certificate_secret_update_callbacks_mutex_);

  auto config_source_it = tls_certificate_secret_update_callbacks_.find(config_source_hash);
  if (config_source_it == tls_certificate_secret_update_callbacks_.end()) {
    tls_certificate_secret_update_callbacks_[config_source_hash][secret_name] = {secret,
                                                                                 {&callback}};
    return;
  }

  auto name_it = config_source_it->second.find(secret_name);
  if (name_it == config_source_it->second.end()) {
    config_source_it->second[secret_name] = {secret, {&callback}};
    return;
  }

  name_it->second.second.push_back(&callback);
}

} // namespace Secret
} // namespace Envoy
