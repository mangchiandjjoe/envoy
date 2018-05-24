#pragma once

#include <shared_mutex>
#include <unordered_map>
#include <vector>

#include "envoy/secret/secret.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/server/instance.h"

#include "common/common/logger.h"
#include "common/secret/sds_api.h"
#include "common/secret/secret_impl.h"

namespace Envoy {
namespace Secret {

class SecretManagerImpl : public SecretManager, Logger::Loggable<Logger::Id::upstream> {
 public:
  SecretManagerImpl(Server::Instance& server)
      : server_(server) {
  }

  virtual ~SecretManagerImpl() {
  }

  bool addOrUpdateStaticSecret(const SecretSharedPtr secret) override;
  const SecretSharedPtr staticSecret(const std::string& name) const override;

  uint64_t
  addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source) override;

  bool addOrUpdateDynamicSecret(const uint64_t config_source_hash, const SecretSharedPtr secret)
      override;
  const SecretSharedPtr dynamicSecret(const uint64_t config_source_hash,
                                      const std::string& name) const override;

  bool removeDynamicSecret(const uint64_t config_source_hash, const std::string& name);


  void registerSecretInitializeCallback(SecretCallbacks& callback) override;

  void registerSecretUpdateCallback(const uint64_t hash, const std::string& name,
                                    SecretCallbacks& callback) override;


  void addPendingClusterName(const std::string cluster_name) override;

  void removePendigClusterName(const std::string cluster_name) override;

  bool isPendingClusterName(const std::string cluster_name) override;

 private:
  Server::Instance& server_;
  SecretSharedPtrMap static_secrets_;
  std::unordered_map<uint64_t, std::unordered_map<std::string, SecretSharedPtr>> dynamic_secrets_;
  std::unordered_map<uint64_t, std::unique_ptr<SdsApi>> sds_apis_;

  mutable std::shared_timed_mutex sds_api_mutex_;
  mutable std::shared_timed_mutex dynamic_secret_mutex_;

  std::vector<SecretCallbacks*> secret_callbacks_;

  struct SecretUpdateCallbackInfo {
    const uint64_t config_source_hash;
    const std::string secret_name;
    SecretSharedPtr secret;
    SecretCallbacks* callback;

    SecretUpdateCallbackInfo(uint64_t config_source_hash_, const std::string secret_name_,
                             const SecretSharedPtr secret_, SecretCallbacks& callback_)
        : config_source_hash(config_source_hash_),
          secret_name(secret_name_),
          secret(secret_),
          callback(&callback_) {
    }
  };

  std::vector<SecretUpdateCallbackInfo> secret_update_callback_;

  std::set<std::string> pending_clusters_;
};

}  // namespace Secret
}  // namespace Envoy
