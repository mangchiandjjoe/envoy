#pragma once

#include <google/protobuf/util/json_util.h>

#include <iomanip>
#include <sstream>
#include <string>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/api/v2/core/config_source.pb.h"
#include "envoy/secret/secret.h"
#include "envoy/secret/secret_callbacks.h"

#include "common/common/fmt.h"
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
   * add or update secret grouped by type.
   * @param sdsConfigSourceHash a hash string of normalized config source. If it is empty string,
   *        find secret from the static secrets.
   * @param secret a shared_ptr of an implementation of Secret.
   */
  virtual void addOrUpdateSecret(const std::string& sdsConfigSourceHash,
                                 const envoy::api::v2::auth::Secret& secret) PURE;

  /**const envoy::api::v2::auth::Secret& secret
   * @param sdsConfigSourceHash hash string of normalized config source.
   * @param name a name of the secret
   * @return the secret in given type. Returns nullptr if the secret is not found.
   */
  virtual const SecretSharedPtr findSecret(Secret::SecretType type,
                                           const std::string& sdsConfigSourceHash,
                                           const std::string& name) const PURE;

  /**
   * @param sdsConfigSourceHash hash string of normalized config source.
   * @param name a name of the secret.
   * @return  The number of elements erased.
   */
  virtual std::size_t removeSecret(Secret::SecretType type,
                                           const std::string& sdsConfigSourceHash,
                                           const std::string& name) PURE;

  /**
   * Add or update SDS config source. SecretManager start downloading secrets from registered
   * config source.
   *
   * @param sdsConfigSource a protobuf message object contains SDS config source.
   * @return a hash string of normalized config source
   */
  virtual std::string addOrUpdateSdsService(
      const envoy::api::v2::core::ConfigSource& sdsConfigSource) PURE;

  /**
   * Register callback function when on secret were updated.
   *
   * @param hash Hash code of ConfigSource
   * @param secret updated SecretSharedPtr
   * @param callback Callback function
   */
  virtual void registerSecretCallbacks(const std::string config_source_hash,
                                       const std::string secret_name, SecretCallbacks& callback)
                                           PURE;

  /**
   * Calculate hash code of ConfigSource. To identify the same ConfigSource, calculate the hash
   * code from the ConfigSource
   *
   * @param  config_source envoy::api::v2::core::ConfigSource
   * @return hash code
   */
  static std::string configSourceHash(const envoy::api::v2::core::ConfigSource& config_source) {
    std::string jsonstr;
    if (google::protobuf::util::MessageToJsonString(config_source, &jsonstr).ok()) {
      auto obj = Json::Factory::loadFromString(jsonstr);
      if (obj.get() != nullptr) {
        return std::to_string(obj->hash());
      }
    }
    throw EnvoyException(
        fmt::format("Invalid ConfigSource message: {}", config_source.DebugString()));
  }
};

} // namespace Secret
} // namespace Envoy
