#pragma once

#include <string>

#include "envoy/config/bootstrap/v2/bootstrap.pb.h"
#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/api/v2/auth/cert.pb.validate.h"

#include "envoy/secret/secret.h"
#include "common/common/hash.h"

namespace Envoy {
namespace Secret {

/**
 * A manager for all secrets and all threaded connection handling workers.
 */
class SecretManager {
 public:
  virtual ~SecretManager() {
  }

  /**
   * Add or update SDS config source
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source)
      PURE;

  /**
   * Add or update secret
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

  virtual bool addOrUpdateDynamicSecret(const std::size_t hash, const SecretPtr secret) PURE;

  virtual bool addOrUpdateDynamicSecrets(const std::size_t hash, const SecretInfoVector& resources)
      PURE;

  /**
   * @return the dynamic secret for the given name
   */
  virtual SecretPtr getDynamicSecret(const std::size_t hash, const std::string& name) PURE;

  static std::size_t configSourceHash(const envoy::api::v2::core::ConfigSource& config_source) {
    std::string text = config_source.DebugString();
    return HashUtil::xxHash64(text);
  }
};

}  // namespace Secret
}  // namespace Envoy

