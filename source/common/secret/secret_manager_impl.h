#pragma once

#include <shared_mutex>
#include <unordered_map>
#include <vector>

#include "envoy/secret/secret.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/server/instance.h"

#include "common/common/logger.h"
#include "common/secret/sds_api.h"
#include "common/ssl/tls_certificate_config_impl.h"

namespace Envoy {
namespace Secret {

class SecretManagerImpl : public SecretManager, Logger::Loggable<Logger::Id::upstream> {
public:
  SecretManagerImpl(Server::Instance& server) : server_(server) {}

  void addOrUpdateSecret(const std::string& sdsConfigSourceHash,
                         const envoy::api::v2::auth::Secret& secret) override;

  const SecretSharedPtr findSecret(Secret::SecretType type, const std::string& sdsConfigSourceHash,
                                   const std::string& name) const override;

  std::size_t removeSecret(Secret::SecretType type, const std::string& sdsConfigSourceHash,
                           const std::string& name) override;

  std::string
  addOrUpdateSdsService(const envoy::api::v2::core::ConfigSource& sdsConfigSource) override;

  void registerSecretAddOrUpdateCallback(const std::string config_source_hash,
                                         const std::string secret_name,
                                         SecretCallbacks& callback) override;

private:
  Server::Instance& server_;

  // Manages pair of name and secret grouped by type of secret and SDS config source. If SDS config
  // source hash is empty, it is a static secret.
  //
  // secret type: {
  //   config source hash: {
  //     name:
  //     secret:
  //   }
  // }
  std::unordered_map<
      Secret::SecretType,
      std::unordered_map<std::string, std::unordered_map<std::string, SecretSharedPtr>>,
      std::hash<int>>
      secrets_;
  mutable std::shared_timed_mutex secrets_mutex_;

  // map hash code of SDS config source and SdsApi object
  std::unordered_map<std::string, std::unique_ptr<SdsApi>> sds_apis_;
  mutable std::shared_timed_mutex sds_api_mutex_;

  // callback functions for secret update
  // "config source hash": {
  //   "secret name": [
  //     {
  //       secret: {},
  //       callback: {}
  //     }
  //   ]
  // }
  std::unordered_map<
      std::string,
      std::unordered_map<std::string, std::vector<std::pair<SecretSharedPtr, SecretCallbacks*>>>>
      secret_update_callbacks_;
  mutable std::shared_timed_mutex secret_update_callbacks_mutex_;
};

} // namespace Secret
} // namespace Envoy
