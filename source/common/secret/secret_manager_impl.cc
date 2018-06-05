#include "common/secret/secret_manager_impl.h"

#include "common/common/logger.h"
#include "common/ssl/tls_certificate_config_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addOrUpdateSecret(const std::string& sds_config_source_hash,
                                          const envoy::api::v2::auth::Secret& secret_config) {
  SecretSharedPtr secret;
  switch (secret_config.type_case()) {
  case envoy::api::v2::auth::Secret::TypeCase::kTlsCertificate:
    secret = std::make_shared<Ssl::TlsCertificateConfigImpl>(secret_config);
    break;
  default:
    throw EnvoyException("Secret type not implemented");
  }

  std::unique_lock<std::shared_timed_mutex> lhs(secrets_mutex_);
  secrets_[secret->type()][sds_config_source_hash][secret->name()] = secret;

  if (!sds_config_source_hash.empty()) {
    server_.dispatcher().post([this, sds_config_source_hash, secret]() {
      // run secret update callbacks
      {
        std::unique_lock<std::shared_timed_mutex> lhs(secret_update_callbacks_mutex_);
        auto config_source_it = secret_update_callbacks_.find(sds_config_source_hash);
        if (config_source_it != secret_update_callbacks_.end()) {
          auto callback_it = config_source_it->second.find(secret->name());
          if (callback_it != config_source_it->second.end()) {
            for (auto& callback : callback_it->second) {
              if (callback.first == nullptr || !callback.first->equalTo(secret)) {
                callback.first = secret;
                callback.second->onAddOrUpdateSecret();
              }
            }
          }
        }
      }
    });
  }
}

const SecretSharedPtr SecretManagerImpl::findSecret(Secret::SecretType type,
                                                    const std::string& sdsConfigSourceHash,
                                                    const std::string& name) const {
  std::shared_lock<std::shared_timed_mutex> lhs(secrets_mutex_);

  auto type_it = secrets_.find(type);
  if (type_it == secrets_.end()) {
    return nullptr;
  }

  auto config_source_it = type_it->second.find(sdsConfigSourceHash);
  if (config_source_it == type_it->second.end()) {
    return nullptr;
  }

  auto name_it = config_source_it->second.find(name);
  if (name_it == config_source_it->second.end()) {
    return nullptr;
  }

  return name_it->second;
}

std::size_t SecretManagerImpl::removeSecret(Secret::SecretType type,
                                            const std::string& sdsConfigSourceHash,
                                            const std::string& name) {
  std::unique_lock<std::shared_timed_mutex> lhs(secrets_mutex_);

  auto type_it = secrets_.find(type);
  if (type_it == secrets_.end()) {
    return 0;
  }

  auto config_source_it = type_it->second.find(sdsConfigSourceHash);
  if (config_source_it == type_it->second.end()) {
    return 0;
  }

  return config_source_it->second.erase(name);
}

std::string SecretManagerImpl::addOrUpdateSdsService(
    const envoy::api::v2::core::ConfigSource& sdsConfigSource) {
  std::unique_lock<std::shared_timed_mutex> lhs(sds_api_mutex_);

  auto hash = SecretManager::configSourceHash(sdsConfigSource);
  if (sds_apis_.find(hash) != sds_apis_.end()) {
    return hash;
  }

  sds_apis_[hash] = std::move(std::make_unique<SdsApi>(server_, sdsConfigSource, *this));

  return hash;
}

void SecretManagerImpl::registerSecretCallbacks(const std::string config_source_hash,
                                                const std::string secret_name,
                                                SecretCallbacks& callback) {
  auto secret = findSecret(Secret::TLS_CERTIFICATE, config_source_hash, secret_name);

  std::unique_lock<std::shared_timed_mutex> lhs(secret_update_callbacks_mutex_);

  auto config_source_it = secret_update_callbacks_.find(config_source_hash);
  if (config_source_it == secret_update_callbacks_.end()) {
    secret_update_callbacks_[config_source_hash][secret_name] = {{secret, &callback}};
    return;
  }

  auto name_it = config_source_it->second.find(secret_name);
  if (name_it == config_source_it->second.end()) {
    config_source_it->second[secret_name] = {{secret, &callback}};
    return;
  }

  name_it->second.push_back({secret, &callback});
}

} // namespace Secret
} // namespace Envoy
