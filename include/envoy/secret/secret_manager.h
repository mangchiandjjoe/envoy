#pragma once

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/api/v2/core/config_source.pb.h"
#include "envoy/secret/secret.h"
#include "envoy/secret/secret_callbacks.h"

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
   * Add or update SDS config source. SecretManager start downloading secrets from registered
   * config source.
   *
   * @param sdsConfigSource a protobuf message object contains SDS config source.
   * @return a hash string of normalized config source
   */
  virtual std::string
  addOrUpdateSdsService(const envoy::api::v2::core::ConfigSource& sdsConfigSource) PURE;

  /**
   * Register callback function when on secret were updated.
   *
   * @param hash Hash code of ConfigSource
   * @param secret updated SecretSharedPtr
   * @param callback Callback function
   */
  virtual void registerSecretCallbacks(const std::string config_source_hash,
                                       const std::string secret_name,
                                       SecretCallbacks& callback) PURE;
};

} // namespace Secret
} // namespace Envoy
