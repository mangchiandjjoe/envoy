#include "common/secret/secret_manager_impl.h"

#include <string>
#include <shared_mutex>

#include "openssl/ssl.h"

#include "envoy/config/bootstrap/v2/bootstrap.pb.h"
#include "envoy/api/v2/auth/cert.pb.h"

#include "envoy/server/instance.h"

#include "common/common/assert.h"
#include "common/common/logger.h"
#include "common/secret/secret_impl.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"
#include "common/config/tls_context_json.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"
#include "common/common/logger.h"

namespace Envoy {
namespace Secret {

SecretManagerImpl::SecretManagerImpl(Server::Instance& server,
                                     envoy::config::bootstrap::v2::SecretManager config)
    : server_(server),
      config_(config) {
}

bool SecretManagerImpl::addOrUpdateSdsConfigSource(
    const envoy::api::v2::core::ConfigSource& config_source) {
  std::size_t hash = SecretManager::configSourceHash(config_source);
  if (sds_apis_.find(hash) != sds_apis_.end()) {
    return true;
  }


  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);


  std::unique_ptr<SdsApi> sds_api(new SdsApi(server_, config_source, *this));
  sds_apis_[hash] = std::move(sds_api);
  dynamic_secrets_[hash] = {};
  return true;
}

bool SecretManagerImpl::addOrUpdateStaticSecret(const SecretPtr secret) {
  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);
  static_secrets_[secret->getName()] = secret;
  return true;
}

bool SecretManagerImpl::addOrUpdateDynamicSecrets(const std::size_t config_source_hash,
                                                  const SecretInfoVector& secrets) {
  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);

  if (dynamic_secrets_.find(config_source_hash) == dynamic_secrets_.end()) {
    ENVOY_LOG(error, "sds: invalid config source");
    return false;
  }

  std::set<std::string> secret_to_be_removed;

  for (auto item : dynamic_secrets_[config_source_hash]) {
    secret_to_be_removed.insert(item.first);
  }

  for (auto secret : secrets) {
    addOrUpdateDynamicSecretInternal(config_source_hash, secret);
    secret_to_be_removed.erase(secret->getName());
  }

// Remove deprecated secrets
  for (auto name : secret_to_be_removed) {
    dynamic_secrets_[config_source_hash].erase(name);
  }

  return true;
}

bool SecretManagerImpl::addOrUpdateDynamicSecret(const std::size_t config_source_hash,
                                                 const SecretPtr secret) {
  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);  // write lock
  return addOrUpdateDynamicSecretInternal(config_source_hash, secret);
}

bool SecretManagerImpl::addOrUpdateDynamicSecretInternal(const std::size_t config_source_hash,
                                                         const SecretPtr secret) {
  if (dynamic_secrets_.find(config_source_hash) == dynamic_secrets_.end()) {
    ENVOY_LOG(error, "sds: secret not found: ", secret->getName());
    return false;
  }

  auto& dynamic_secrets = dynamic_secrets_[config_source_hash];

  if (dynamic_secrets.find(secret->getName()) != dynamic_secrets.end()) {
    if (dynamic_secrets[secret->getName()]->getCertificateChain() == secret->getCertificateChain()
        && dynamic_secrets[secret->getName()]->getPrivateKey() == secret->getPrivateKey()) {
      // Certificate chain and private key are same as locally cached. No need to update
      ENVOY_LOG(debug, "sds: no need to update '{}' skipped", secret->getName());
      return true;
    }
  }

  auto old_secret = dynamic_secrets[secret->getName()];
  dynamic_secrets[secret->getName()] = secret;

  if (&server_.clusterManager() != nullptr && &server_.listenerManager() != nullptr) {
    // Create pending cluster or update secret
    if (!server_.clusterManager().sdsSecretUpdated(secret->getName())) {
      // In case of failure, revert back to the previous secret
      dynamic_secrets[secret->getName()] = old_secret;
      return false;
    }

    // Create pending listener or update secret
    if (!server_.listenerManager().sdsSecretUpdated(secret->getName())) {
      // In case of failure, revert back to the previous secret
      dynamic_secrets[secret->getName()] = old_secret;
      return false;
    }
  }

  return true;
}

bool SecretManagerImpl::removeDynamicSecret(const std::size_t config_source_hash,
                                            const std::string& name) {

  if (dynamic_secrets_.find(config_source_hash) != dynamic_secrets_.end()
      && dynamic_secrets_[config_source_hash].find(name)
          != dynamic_secrets_[config_source_hash].end()) {
    dynamic_secrets_[config_source_hash].erase(name);
  }

  return true;
}

SecretPtr SecretManagerImpl::getStaticSecret(const std::string& name) {
  return (static_secrets_.find(name) != static_secrets_.end()) ? static_secrets_[name] : nullptr;
}

SecretPtr SecretManagerImpl::getDynamicSecret(const std::size_t config_source_hash,
                                              const std::string& name) {
  if (dynamic_secrets_.find(config_source_hash) != dynamic_secrets_.end()
      && dynamic_secrets_[config_source_hash].find(name)
          != dynamic_secrets_[config_source_hash].end()) {
    return dynamic_secrets_[config_source_hash][name];
  }

  return nullptr;
}

}  // namespace Secret
}  // namespace Envoy
