#pragma once

#include <shared_mutex>
#include <unordered_map>

#include "envoy/config/bootstrap/v2/bootstrap.pb.h"

#include "envoy/server/instance.h"
#include "envoy/server/worker.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/secret/secret.h"

#include "common/common/logger.h"
#include "common/secret/secret_impl.h"
#include "common/secret/sds_api.h"

namespace Envoy {
namespace Secret {

class SecretManagerImpl : public SecretManager, Logger::Loggable<Logger::Id::upstream> {
 public:
  SecretManagerImpl(Server::Instance& server, envoy::config::bootstrap::v2::SecretManager config);

  virtual ~SecretManagerImpl() {
  }

  // override from SecretManager
  bool addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source) override;

  bool addOrUpdateStaticSecret(const SecretPtr secret) override;

  bool addOrUpdateDynamicSecret(const uint64_t config_source_hash, const SecretPtr secret)
      override;

  bool addOrUpdateDynamicSecrets(const uint64_t config_source_hash,
                                 const SecretInfoVector& resources) override;

  SecretPtr getStaticSecret(const std::string& name) override;
  SecretPtr getDynamicSecret(const uint64_t config_source_hash, const std::string& name)
      override;

  // SecretManagerImpl
  bool removeDynamicSecret(const uint64_t config_source_hash, const std::string& name);

  bool addOrUpdateDynamicSecretInternal(const uint64_t config_source_hash,
                                        const SecretPtr secret);

 private:
  Server::Instance& server_;
  SecretInfoMap secrets_;

  SecretInfoMap static_secrets_;
  std::unordered_map<uint64_t, SecretInfoMap> dynamic_secrets_;

  envoy::config::bootstrap::v2::SecretManager config_;
  std::unordered_map<uint64_t, std::unique_ptr<SdsApi>> sds_apis_;
  mutable std::shared_timed_mutex mutex_;
};

}  // namespace Secret
}  // namespace Envoy
