#include "common/config/sds_json.h"

#include "common/common/assert.h"
#include "common/config/address_json.h"
#include "common/config/json_utility.h"
//#include "common/config/tls_context_json.h"
#include "common/config/utility.h"
#include "common/config/well_known_names.h"
#include "common/json/config_schemas.h"
#include "common/network/utility.h"

namespace Envoy {
namespace Config {
/*
void SdsJson::translateSecret(const Json::Object& json_secret,
                              envoy::api::v2::auth::Secret& secret) {
  //json_secret.validateSchema(Json::Schema::SECRET_SCHEMA);

  const std::string name = json_secret.getString("name", "");

  if (json_secret.hasObject("tls_certificate")) {
    auto tls_certificate = json_secret.getObject("tls_certificate");

    auto mutable_tls_certificate = secret.mutable_tls_certificate();
    if (tls_certificate->hasObject("certificate_chain")) {
      auto certificate_chain = tls_certificate->getObject("certificate_chain");
      auto mutable_certificate_chain = mutable_tls_certificate
          ->mutable_certificate_chain();

      if (certificate_chain->hasObject("filename")) {
        mutable_certificate_chain->set_filename(
            certificate_chain->getString("filename"));
      } else if (certificate_chain->hasObject("inline_bytes")) {
        mutable_certificate_chain->set_inline_bytes(
            certificate_chain->getString("inline_bytes"));
      } else if (certificate_chain->hasObject("inline_string")) {
      }
    }

    if (tls_certificate->hasObject("private_key")) {
      // error
    }

  } else if (json_secret.hasObject("session_ticket_keys")) {
  } else {
    // err
  }
}
*/
void SdsJson::translateConfigSource(
    const Json::Object& json_config_source,
    envoy::api::v2::core::ConfigSource& config_source) {
  //json_config_source.validateSchema(Json::Schema::...);

  if (json_config_source.getString("path").length() > 0) {
    config_source.set_path(json_config_source.getString("path"));
  } else if (json_config_source.getObject("api_config_source")) {
    SdsJson::translateApiConfigSource(
        *json_config_source.getObject("api_config_source"),
        *config_source.mutable_api_config_source());
  } else if (json_config_source.getObject("ads")) {
    // empty
  } else {
    // error
  }
}

void SdsJson::translateApiConfigSource(
    const Json::Object& json_api_config_source,
    envoy::api::v2::core::ApiConfigSource& api_config_source) {
  //json_api_config_source.validateSchema(Json::Schema::...);

  switch (json_api_config_source.getInteger("api_type")) {
    case api_config_source.REST:
      api_config_source.set_api_type(api_config_source.REST);
      break;
    case api_config_source.GRPC:
      api_config_source.set_api_type(api_config_source.GRPC);
      break;
    case api_config_source.REST_LEGACY:
      api_config_source.set_api_type(api_config_source.REST_LEGACY);
      break;
    default:
      // error
      break;
  }

  for (auto cluster_name : json_api_config_source.getStringArray("cluster_names")) {
    *api_config_source.mutable_cluster_names()->Add()=cluster_name;
  }

  for (auto grpc_service : json_api_config_source.getObjectArray("grpc_services")) {

  }

  // TODO(jaebong) how can I handle google protobuf
  //Protobuf::util::TimeUtil::DurationToMilliseconds(message_->load_reporting_interval()))
}
/*
void SdsJson::translateSdsSecretConfig(const Json::Object& json_sds_secret_config, envoy::api::v2::auth::SdsSecretConfig& sds_secret_config) {
  //json_sds_secret_config.validateSchema(Json::Schema::...);

  sds_secret_config.set_name(json_sds_secret_config.getString("name"));

  if (json_sds_secret_config.hasObject("sds_config")) {
    SdsJson::translateConfigSource(
        *json_sds_secret_config.getObject("sds_config"),
        *sds_secret_config.mutable_sds_config())
  }
}
*/
}  // namespace Upstream
}  // namespace Envoy































