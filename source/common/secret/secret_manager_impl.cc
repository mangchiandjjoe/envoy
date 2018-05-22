#include "common/secret/secret_manager_impl.h"

#include "common/common/logger.h"
#include "common/secret/secret_impl.h"

namespace Envoy {
namespace Secret {

bool SecretManagerImpl::addOrUpdateStaticSecret(const SecretSharedPtr secret) {
  static_secrets_[secret->name()] = secret;
  return true;
}

const SecretSharedPtr SecretManagerImpl::staticSecret(const std::string& name) const {
  auto static_secret = static_secrets_.find(name);
  return (static_secret != static_secrets_.end()) ? static_secret->second : nullptr;
}

uint64_t SecretManagerImpl::addOrUpdateSdsConfigSource(
    const envoy::api::v2::core::ConfigSource& config_source) {

  std::unique_lock<std::shared_timed_mutex> lhs(sds_api_mutex_);

  uint64_t hash = SecretManager::configSourceHash(config_source);

  if (sds_apis_.find(hash) != sds_apis_.end()) {
    return hash;
  }

  std::unique_ptr<SdsApi> sds_api(new SdsApi(server_, config_source, *this));
  sds_apis_[hash] = std::move(sds_api);
  dynamic_secrets_[hash] = {};
  return hash;
}

bool SecretManagerImpl::addOrUpdateDynamicSecret(const uint64_t config_source_hash,
                                                 const SecretSharedPtr secret) {

  std::unique_lock<std::shared_timed_mutex> lhs(dynamic_secret_mutex_);

  auto sds_service = dynamic_secrets_.find(config_source_hash);
  if (sds_service == dynamic_secrets_.end()) {
    ENVOY_LOG(error, "sds: ConfigSource not found: ", secret->name());
    return false;
  }

  sds_service->second[secret->name()] = secret;

  // Post callback to call registered SecretCallbacks functions
  std::function<void()> lambda = [this, config_source_hash, secret]() {
    for (const auto& callback : secret_callbacks_) {
      callback->onAddOrUpdateSecret(config_source_hash, secret);
    }
  };
  server_.dispatcher().post(lambda);

  return true;
}

const SecretSharedPtr SecretManagerImpl::dynamicSecret(const uint64_t config_source_hash,
                                                       const std::string& name) const {
  std::shared_lock<std::shared_timed_mutex> lhs(dynamic_secret_mutex_);

  auto sds_service = dynamic_secrets_.find(config_source_hash);
  if (sds_service == dynamic_secrets_.end()) {
    ENVOY_LOG(error, "sds: ConfigSource not found: ", name);
    return nullptr;
  }

  auto dynamic_secret = sds_service->second.find(name);
  if (dynamic_secret == sds_service->second.end()) {
    ENVOY_LOG(info, "sds: Secret not found: ", name);
    return nullptr;
  }

  return dynamic_secret->second;
}

bool SecretManagerImpl::removeDynamicSecret(const uint64_t config_source_hash,
                                            const std::string& name) {
  std::unique_lock<std::shared_timed_mutex> lhs(dynamic_secret_mutex_);

  auto sds_service = dynamic_secrets_.find(config_source_hash);
  if (sds_service == dynamic_secrets_.end()) {
    ENVOY_LOG(error, "sds: ConfigSource not found: ", name);
    return false;
  }

  auto dynamic_secret = sds_service->second.find(name);
  if (dynamic_secret == sds_service->second.end()) {
    ENVOY_LOG(error, "sds: Secret not found: ", name);
    return false;
  }

  sds_service->second.erase(name);

  return true;
}

void SecretManagerImpl::registerSecretCallback(SecretCallbacks& callback) {
  secret_callbacks_.push_back(&callback);
}

} // namespace Secret
} // namespace Envoy
