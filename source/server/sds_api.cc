#include "server/sds_api.h"

#include <unordered_map>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/api/v2/auth/cert.pb.validate.h"

#include "common/common/cleanup.h"
#include "common/config/resources.h"
#include "common/config/subscription_factory.h"
#include "common/config/utility.h"
#include "common/protobuf/utility.h"

#include "envoy/ssl/secret.h"

#include "server/sds_subscription.h"
#include "envoy/server/secret_manager.h"

namespace Envoy {
namespace Server {

SdsApi::SdsApi(const envoy::api::v2::core::ConfigSource& sds_config,
               Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
               Runtime::RandomGenerator& random, Init::Manager& init_manager,
               const LocalInfo::LocalInfo& local_info, Stats::Scope& scope,
               Envoy::Server::SecretManager& sm)
    : secret_manager_(sm),
      scope_(scope.createScope("secret_manager.lds.")),
      cm_(cm) {

  subscription_ =
      Envoy::Config::SubscriptionFactory::subscriptionFromConfigSource<
          envoy::api::v2::auth::Secret>(
          sds_config,
          local_info.node(),
          dispatcher,
          cm,
          random,
          *scope_,
          [this, &sds_config, &cm, &dispatcher, &random,
          &local_info]() -> Config::Subscription<envoy::api::v2::auth::Secret>* {
            return new SdsSubscription(Config::Utility::generateStats(*scope_), sds_config, cm,
                dispatcher, random, local_info);
          },
          "envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets",
          "envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets");

  Config::Utility::checkLocalInfo("sds", local_info);
  init_manager.registerTarget(*this);
}

void SdsApi::initialize(std::function<void()> callback) {
  initialize_callback_ = callback;
  subscription_->start({}, *this);
}

void SdsApi::onConfigUpdate(const ResourceVector& resources) {
  cm_.adsMux().pause(Config::TypeUrl::get().RouteConfiguration);

  Cleanup sds_resume(
      [this] {cm_.adsMux().resume(Config::TypeUrl::get().RouteConfiguration);});

  for (const auto& secret : resources) {
    MessageUtil::validate(secret);
  }

  // We need to keep track of which secrets we might need to remove.
  SecretManager::SecretInfoMap secrets_to_remove;
  for (const auto& elem : secret_manager_.secrets()) {
    secrets_to_remove.emplace(elem.first, elem.second);
  }

  for (const auto& secret : resources) {
    const std::string secret_name = secret.name();

    ENVOY_LOG(info, "*** {}", secret_name);
    secrets_to_remove.erase(secret_name);
    if (secret_manager_.addOrUpdateSecret(secret)) {
      ENVOY_LOG(info, "sds: add/update secret '{}'", secret_name);
    } else {
      ENVOY_LOG(debug, "sds: add/update secret '{}' skipped", secret_name);
    }
  }

  for (const auto& elem : secrets_to_remove) {
    if (secret_manager_.removeSecret(elem.first)) {
      ENVOY_LOG(info, "sds: remove secret '{}'", elem.first);
    }
  }

  runInitializeCallbackIfAny();
}

void SdsApi::onConfigUpdateFailed(const EnvoyException*) {
// We need to allow server startup to continue, even if we have a bad
// config.
  runInitializeCallbackIfAny();
}

void SdsApi::runInitializeCallbackIfAny() {
  if (initialize_callback_) {
    initialize_callback_();
    initialize_callback_ = nullptr;
  }
}

}  // namespace Server
}  // namespace Envoy
