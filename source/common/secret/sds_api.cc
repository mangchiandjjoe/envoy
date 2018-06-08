#include "common/secret/sds_api.h"

#include <unordered_map>

#include "common/config/resources.h"
#include "common/config/subscription_factory.h"
#include "common/secret/sds_subscription.h"
#include "common/secret/secret_manager_util.h"

namespace Envoy {
namespace Secret {

SdsApi::SdsApi(Server::Instance& server, const envoy::api::v2::core::ConfigSource& sds_config)
    : server_(server), sds_config_(sds_config),
      sds_config_source_hash_(SecretManagerUtil::configSourceHash(sds_config)) {
  server_.initManager().registerTarget(*this);
}

void SdsApi::initialize(std::function<void()> callback) {
  initialize_callback_ = callback;
  subscription_ = Envoy::Config::SubscriptionFactory::subscriptionFromConfigSource<
      envoy::api::v2::auth::Secret>(
      sds_config_, server_.localInfo().node(), server_.dispatcher(), server_.clusterManager(),
      server_.random(), server_.stats(),
      [this]() -> Config::Subscription<envoy::api::v2::auth::Secret>* {
        return new SdsSubscription(Config::Utility::generateStats(this->server_.stats()),
                                   this->sds_config_, this->server_.clusterManager(),
                                   this->server_.dispatcher(), this->server_.random(),
                                   this->server_.localInfo());
      },
      "envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets",
      // TODO(jaebong) replace next line with
      // "envoy.service.discovery.v2.SecretDiscoveryService.StreamSecrets" to support streaming
      // service
      "envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets");

  Config::Utility::checkLocalInfo("sds", server_.localInfo());

  subscription_->start({}, *this);
}

void SdsApi::onConfigUpdate(const ResourceVector& resources, const std::string&) {
  for (const auto& resource : resources) {
    switch (resource.type_case()) {
    case envoy::api::v2::auth::Secret::kTlsCertificate:
      server_.secretManager().addOrUpdateSecret(sds_config_source_hash_, resource);
      break;
    case envoy::api::v2::auth::Secret::kSessionTicketKeys:
      NOT_IMPLEMENTED
    default:
      throw EnvoyException("sds: invalid configuration");
    }
  }

  runInitializeCallbackIfAny();
}

void SdsApi::onConfigUpdateFailed(const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad config.
  runInitializeCallbackIfAny();
}

void SdsApi::runInitializeCallbackIfAny() {
  if (initialize_callback_) {
    initialize_callback_();
    initialize_callback_ = nullptr;
  }
}

} // namespace Secret
} // namespace Envoy
