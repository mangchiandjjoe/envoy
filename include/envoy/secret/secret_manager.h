#pragma once

#include <string>
#include <sstream>
#include <iomanip>

#include <google/protobuf/util/json_util.h>

#include "envoy/secret/secret.h"
#include "envoy/config/bootstrap/v2/bootstrap.pb.h"
#include "common/json/json_loader.h"

namespace Envoy {
namespace Secret {

/**
 * A manager for all static and dynamic secrets and all threaded connection handling workers.
 */
class SecretManager {
 public:
  virtual ~SecretManager() {
  }

  /**
   * Add or update SDS config source
   *
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source)
      PURE;

  /**
   * Add or update static secret
   *
   * @param config_source ConfigSource of updated secret
   * @param secret Updated Secret
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateStaticSecret(const SecretPtr secret) PURE;

  /**
   * @return the static secret for the given name
   */
  virtual SecretPtr getStaticSecret(const std::string& name) PURE;

  /**
   * Add or update dynamic secret
   *
   * @param hash Hash code of ConfigSource
   * @param secret new or updated SecretPtr
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateDynamicSecret(const uint64_t hash, const SecretPtr secret) PURE;

  /**
   * Add or update dynamic secrets
   *
   * @param hash Hash code of ConfigSource
   * @param secrets list of new or updated SecretPtr
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateDynamicSecrets(const uint64_t hash, const SecretInfoVector& secrets) PURE;

  /**
   * @return the dynamic secret for the given ConfigSource and secret name
   */
  virtual SecretPtr getDynamicSecret(const uint64_t hash, const std::string& name) PURE;

  /**
   * Calculate hash code of ConfigSource. To identify the same ConfigSource, calculate the hash
   * code from the ConfigSource
   *
   * @param  config_source envoy::api::v2::core::ConfigSource
   * @return hash code
   */
  static uint64_t configSourceHash(const envoy::api::v2::core::ConfigSource& config_source) {
    std::string jsonstr;
    if (google::protobuf::util::MessageToJsonString(config_source, &jsonstr).ok()) {
      auto obj = Json::Factory::loadFromString(jsonstr);
      if (obj.get() != nullptr) {
        return obj->hash();
      }
    }
    throw EnvoyException("invalid ConfigSource message");
  }
};

}  // namespace Secret
}  // namespace Envoy

