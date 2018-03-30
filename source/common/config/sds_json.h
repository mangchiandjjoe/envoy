#pragma once

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/json/json_object.h"

namespace Envoy {
namespace Config {

class SdsJson {
 public:
  /**
   */
  static void translateSecret(const Json::Object& json_secret,
                              envoy::api::v2::auth::Secret& secret);

  static void translateSdsSecretConfig(
      const Json::Object& json_sds_secret_config,
      envoy::api::v2::auth::SdsSecretConfig& sds_secret_config);

  static void translateConfigSource(
      const Json::Object& json_config_source,
      envoy::api::v2::core::ConfigSource & api_config_source);

  static void translateApiConfigSource(
      const Json::Object& json_api_config_source,
      envoy::api::v2::core::ApiConfigSource & api_config_source);
};

}  // namespace Config
}  // namespace Envoy
