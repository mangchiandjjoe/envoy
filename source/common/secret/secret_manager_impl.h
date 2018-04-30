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

  bool addOrUpdateSecret(const envoy::api::v2::auth::Secret& config, bool is_static) override;

  SecretInfoMap& secrets() override {
    return secrets_;
  }

  SecretPtr getSecret(const std::string& name, bool is_static) override;

  bool removeSecret(const std::string& name) override;

  bool addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source) override;

 private:
  const std::string readDataSource(const envoy::api::v2::core::DataSource& source,
                                   bool allow_empty);

  const std::string getDataSourcePath(const envoy::api::v2::core::DataSource& source);

  Server::Instance& server_;
  SecretInfoMap secrets_;
  envoy::config::bootstrap::v2::SecretManager config_;
  std::unordered_map<std::size_t, std::unique_ptr<SdsApi>> sds_apis_;
  mutable std::shared_timed_mutex mutex_;
};

}  // namespace Secret
}  // namespace Envoy
