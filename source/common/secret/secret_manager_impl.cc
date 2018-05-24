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
  std::function<void()> secret_update_callback = [this, config_source_hash, secret]() {
    // running secret update callback function
    for (auto& update_callback : secret_update_callback_) {
      if(update_callback.config_source_hash == config_source_hash &&
          update_callback.secret_name == secret->name() &&
          update_callback.secret->certificateChain() != secret->certificateChain() &&
          update_callback.secret->privateKey() != secret->privateKey()) {
        update_callback.callback->onAddOrUpdateSecret();
        update_callback.secret = secret;
      }
    }

    // running secret initialization callback functions
    for (const auto& callback : secret_callbacks_) {
      callback->onAddOrUpdateSecret();
    }

  };
  server_.dispatcher().post(secret_update_callback);

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

void SecretManagerImpl::registerSecretInitializeCallback(SecretCallbacks& callback) {
  secret_callbacks_.push_back(&callback);
}

void SecretManagerImpl::registerSecretUpdateCallback(const uint64_t hash, const std::string& name,
                                                     SecretCallbacks& callback) {
  auto secret = dynamicSecret(hash, name);
  if(secret) {
    secret_update_callback_.push_back({hash, name, secret, callback});
  }
}

void SecretManagerImpl::addPendingClusterName(const std::string cluster_name) {
  pending_clusters_.emplace(cluster_name);
}

void SecretManagerImpl::removePendigClusterName(const std::string cluster_name) {
  pending_clusters_.erase(cluster_name);
}

bool SecretManagerImpl::isPendingClusterName(const std::string cluster_name) {
  return pending_clusters_.find(cluster_name) != pending_clusters_.end();
}


} // namespace Secret
} // namespace Envoy
