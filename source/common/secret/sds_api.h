#pragma once

#include <functional>
#include <vector>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/server/instance.h"

#include "common/common/logger.h"

namespace Envoy {
namespace Secret {

/**
 * SDS API implementation that fetches secrets from SDS server via Subscription.
 */
class SdsApi : public Init::Target,
               Config::SubscriptionCallbacks<envoy::api::v2::auth::Secret>,
               Logger::Loggable<Logger::Id::upstream> {

public:
  SdsApi(Server::Instance& server, const envoy::api::v2::core::ConfigSource& sds_config,
         SecretManager& secret_manager);

  virtual ~SdsApi() {}

  // Init::Target
  void initialize(std::function<void()> callback) override;

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources, const std::string& version_info) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    return MessageUtil::anyConvert<envoy::api::v2::auth::Secret>(resource).name();
  }

private:
  void runInitializeCallbackIfAny();

  Server::Instance& server_;
  const envoy::api::v2::core::ConfigSource sds_config_;
  const uint64_t sds_config_source_hash_;
  SecretManager& secret_manager_;
  std::unique_ptr<Config::Subscription<envoy::api::v2::auth::Secret>> subscription_;
  std::function<void()> initialize_callback_;
};

} // namespace Secret
} // namespace Envoy
