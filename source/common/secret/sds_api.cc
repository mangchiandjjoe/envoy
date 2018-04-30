#include <envoy/secret/secret.h>

#include <unordered_map>
#include <set>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/api/v2/auth/cert.pb.validate.h"
#include "envoy/secret/secret_manager.h"

#include "common/common/cleanup.h"
#include "common/config/resources.h"
#include "common/config/subscription_factory.h"
#include "common/config/utility.h"
#include "common/protobuf/utility.h"
#include "common/secret/sds_api.h"
#include "common/secret/sds_subscription.h"

namespace Envoy {
namespace Secret {

SdsApi::SdsApi(Server::Instance& server, const envoy::api::v2::core::ConfigSource& sds_config,
               SecretManager& secret_manager)
    : server_(server),
      sds_config_([&sds_config] {
        envoy::api::v2::core::ConfigSource cfg;
        cfg.CopyFrom(sds_config);
        return cfg;
      }()),
      secret_manager_(secret_manager) {
  server_.initManager().registerTarget(*this);
}

void SdsApi::initialize(std::function<void()> callback) {
  initialize_callback_ = callback;

  subscription_ = Envoy::Config::SubscriptionFactory::subscriptionFromConfigSource<
      envoy::api::v2::auth::Secret>(
      sds_config_, server_.localInfo().node(), server_.dispatcher(), server_.clusterManager(),
      server_.random(), server_.stats(),
      [this]() -> Config::Subscription<envoy::api::v2::auth::Secret>* {
        return new SdsSubscription(
            Config::Utility::generateStats(this->server_.stats()),
            this->sds_config_, this->server_.clusterManager(),
            this->server_.dispatcher(), this->server_.random(),
            this->server_.localInfo());
      },
      "envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets",
      "envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets");

  Config::Utility::checkLocalInfo("sds", server_.localInfo());

  subscription_->start({}, *this);
}

void SdsApi::onConfigUpdate(const ResourceVector& resources) {
  for (const auto& secret : resources) {
    MessageUtil::validate(secret);
  }

  std::set<std::string> secrets_to_be_removed;
  for (const auto& secret : secret_manager_.secrets()) {
    if(!secret.second->isStatic()) {
      secrets_to_be_removed.insert(secret.first);
    }
  }

  for (const auto& secret : resources) {
    // All secrets downloaded through the SdsApi are dynamic
    secrets_to_be_removed.erase(secret.name());
    if (secret_manager_.addOrUpdateSecret(secret, false)) {
      ENVOY_LOG(info, "sds: add/update secret '{}'", secret.name());
    }
  }

  for(const auto& name : secrets_to_be_removed) {
    secret_manager_.removeSecret(name);
    ENVOY_LOG(info, "sds: removed secret '{}'", name);
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

}  // namespace Secret
}  // namespace Envoy
