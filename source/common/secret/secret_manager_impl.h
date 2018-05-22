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
  SecretManagerImpl(Server::Instance& server) : server_(server) {}

  virtual ~SecretManagerImpl() {}

  bool addOrUpdateStaticSecret(const SecretSharedPtr secret) override;
  const SecretSharedPtr staticSecret(const std::string& name) const override;

  uint64_t
  addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source) override;

  bool addOrUpdateDynamicSecret(const uint64_t config_source_hash,
                                const SecretSharedPtr secret) override;
  const SecretSharedPtr dynamicSecret(const uint64_t config_source_hash,
                                      const std::string& name) const override;

  bool removeDynamicSecret(const uint64_t config_source_hash, const std::string& name);

  void registerSecretCallback(SecretCallbacks& callback) override;

private:
  Server::Instance& server_;
  SecretSharedPtrMap static_secrets_;
  std::unordered_map<uint64_t, std::unordered_map<std::string, SecretSharedPtr>> dynamic_secrets_;
  std::unordered_map<uint64_t, std::unique_ptr<SdsApi>> sds_apis_;

  mutable std::shared_timed_mutex sds_api_mutex_;
  mutable std::shared_timed_mutex dynamic_secret_mutex_;

  std::vector<SecretCallbacks*> secret_callbacks_;

  std::function<void()> secret_update_callback_;
};

} // namespace Secret
} // namespace Envoy
