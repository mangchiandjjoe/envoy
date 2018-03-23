#pragma once

#include <vector>
#include <functional>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/init/init.h"
#include "envoy/server/listener_manager.h"
#include "envoy/server/secret_manager.h"

#include "common/common/logger.h"

namespace Envoy {
namespace Server {

/**
 * SDS API implementation that fetches via Subscription.
 */
class SdsApi : public Init::Target,
                      Config::SubscriptionCallbacks<envoy::api::v2::auth::Secret>,
                      Logger::Loggable<Logger::Id::upstream> {

 public:
  SdsApi(const envoy::api::v2::core::ConfigSource& sds_config,
         Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
         Runtime::RandomGenerator& random, Init::Manager& init_manager,
         const LocalInfo::LocalInfo& local_info, Stats::Scope& scope,
         Envoy::Server::SecretManager& sm);

  virtual ~SdsApi() {
  }

  const std::string versionInfo() const {
    return subscription_->versionInfo();
  }

  const std::string getCertificateChain() {
    return tls_certificate_certificate_chain_;
  }

  const std::string getPrivateKey() {
    return tls_certificate_private_key_;
  }

  const std::vector<std::string>& getSessionTicketKeys() {
    return session_ticket_keys_;
  }

  // Init::Target
  void initialize(std::function<void()> callback) override;

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    return MessageUtil::anyConvert<envoy::api::v2::Listener>(resource).name();
  }

 private:
  void runInitializeCallbackIfAny();

 private:
  std::unique_ptr<Config::Subscription<envoy::api::v2::auth::Secret>> subscription_;
  SecretManager& secret_manager_;
  Stats::ScopePtr scope_;
  Upstream::ClusterManager& cm_;
  std::function<void()> initialize_callback_;

 private:
  // tls_certificate
  std::string tls_certificate_certificate_chain_;
  std::string tls_certificate_private_key_;

  // session_ticket_keys
  std::vector<std::string> session_ticket_keys_;
};

}  // namespace Server
}  // namespace Envoy
