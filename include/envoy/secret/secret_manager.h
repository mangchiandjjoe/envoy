#pragma once

#include <google/protobuf/util/json_util.h>

#include <iomanip>
#include <sstream>
#include <string>

#include "envoy/secret/secret.h"
#include "envoy/api/v2/core/config_source.pb.h"

#include "common/json/json_loader.h"

namespace Envoy {
namespace Secret {

/**
 * A manager for all static secrets
 */
class SecretManager {
public:
  virtual ~SecretManager() {}

  /**
   * Add or update static secret.
   *
   * @param secret Updated Secret
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateStaticSecret(const SecretSharedPtr secret) PURE;

  /**
   * @return the static secret for the given name.
   */
  virtual const SecretSharedPtr staticSecret(const std::string& name) const PURE;

  /**
   *
   */
  virtual uint64_t addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source) PURE;

  /**
   * Add or update dynamic secret
   *
   * @param hash Hash code of ConfigSource
   * @param secret new or updated SecretPtr
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateDynamicSecret(const uint64_t hash, const SecretSharedPtr secret) PURE;

  /**
   * @return the dynamic secret for the given ConfigSource and secret name.
   */
  virtual const SecretSharedPtr dynamicSecret(const uint64_t hash, const std::string& name) const PURE;


  /**
   * Register callback function for certificate initial download.
   *
   * @param callback Callback function
   */
  virtual void registerSecretInitializeCallback(SecretCallbacks& callback) PURE;

  /**
   * Register callback function when dynamic secrets were updated.
   *
   * @param hash Hash code of ConfigSource
   * @param secret updated SecretSharedPtr
   * @param callback Callback function
   */
  virtual void registerSecretUpdateCallback(const uint64_t config_source_hash,
                                            const std::string& secret_name,
                                            SecretCallbacks& callback) PURE;

  virtual void addPendingClusterName(const std::string cluster_name) PURE;

  virtual void removePendigClusterName(const std::string cluster_name) PURE;

  virtual bool isPendingClusterName(const std::string cluster_name) PURE;

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

} // namespace Secret
} // namespace Envoy
