#include "common/secret/sds_subscription.h"

#include <vector>

#include "common/common/fmt.h"
#include "common/config/utility.h"
#include "common/http/headers.h"
#include "common/json/config_schemas.h"
#include "common/json/json_loader.h"
#include "common/config/tls_context_json.h"

namespace Envoy {
namespace Server {

SdsSubscription::SdsSubscription(
    Config::SubscriptionStats stats,
    const envoy::api::v2::core::ConfigSource& sds_config,
    Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
    Runtime::RandomGenerator& random, const LocalInfo::LocalInfo& local_info)
    : Http::RestApiFetcher(
          cm,
          sds_config.api_config_source().cluster_names()[0],
          dispatcher,
          random,
          Config::Utility::apiConfigSourceRefreshDelay(
              sds_config.api_config_source())),
      stats_(stats),
      local_info_(local_info) {

  const auto& api_config_source = sds_config.api_config_source();

  UNREFERENCED_PARAMETER(api_config_source);

  // If we are building an CdsSubscription, the ConfigSource should be REST_LEGACY.
  ASSERT(
      api_config_source.api_type()
          == envoy::api::v2::core::ApiConfigSource::REST_LEGACY);

  // TODO(htuch): Add support for multiple clusters, #1170.
  ASSERT(api_config_source.cluster_names().size() == 1);
  ASSERT(api_config_source.has_refresh_delay());
}

void SdsSubscription::createRequest(Http::Message& request) {
  ENVOY_LOG(debug, "sds: starting request");

  stats_.update_attempt_.inc();

  request.headers().insertMethod().value().setReference(
      Http::Headers::get().MethodValues.Get);

  request.headers().insertPath().value(
      fmt::format("/v1/secrets/{}", local_info_.nodeName()));
}

void SdsSubscription::parseResponse(const Http::Message& response) {
  ENVOY_LOG(debug, "sds: parsing response");

  const std::string response_body = response.bodyAsString();

  Json::ObjectSharedPtr response_json = Json::Factory::loadFromString(
      response_body);

//  response_json->validateSchema(Json::Schema::SECRET_SCHEMA);

  std::vector<Json::ObjectSharedPtr> secrets = response_json->getObjectArray(
      "secrets");

  Protobuf::RepeatedPtrField<envoy::api::v2::auth::Secret> resources;
  for (const Json::ObjectSharedPtr& secret : secrets) {
    auto resource = *resources.Add();

    resource.set_name(secret->getString("name"));

    if (secret->hasObject("tls_certificate")) {
      Envoy::Config::TlsContextJson::translateTlsCertificate(
          *secret->getObject("tls_certificate"),
          *resource.mutable_tls_certificate());
    } else if (secret->hasObject("session_ticket_keys")) {
      // TODO(jaebong) implement this
      throw EnvoyException("session_ticket_keys is not implemented");
    } else {
      throw EnvoyException(
          fmt::format(
              "either tls_certificate or session_ticket_keys for %s should be configured",
              secret->getString("name")));
    }
  }

  callbacks_->onConfigUpdate(resources);

  std::pair<std::string, uint64_t> hash =
      Envoy::Config::Utility::computeHashedVersion(response_body);

  version_info_ = hash.first;
  stats_.version_.set(hash.second);
  stats_.update_success_.inc();
}

void SdsSubscription::onFetchComplete() {
  ENVOY_LOG(debug, "sds: fetch complete");
}

void SdsSubscription::onFetchFailure(const EnvoyException* e) {
  ENVOY_LOG(info, "sds: fetch failure");
  callbacks_->onConfigUpdateFailed(e);
  stats_.update_failure_.inc();
  if (e) {
    ENVOY_LOG(warn, "sds: fetch failure: {}", e->what());
  } else {
    ENVOY_LOG(debug, "sds: fetch failure: network error");
  }
}

}  // namespace Server
}  // namespace Envoy
