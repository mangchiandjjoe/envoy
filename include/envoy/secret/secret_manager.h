#pragma once

#include <string>

#include "envoy/config/bootstrap/v2/bootstrap.pb.h"
#include "envoy/secret/secret.h"

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
  virtual bool addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source) PURE;

  /**
   * Add or update secret
   * @return true when successful, otherwise returns false
   */
  virtual bool addOrUpdateSecret(const envoy::api::v2::auth::Secret& config, bool is_static) PURE;

  /**
   * @return map of secrets
   */
  virtual SecretInfoMap& secrets() PURE;

  /**
   * @return the secret for the given name
   */
  virtual SecretPtr getSecret(const std::string& name, bool is_static) PURE;

  /**
   * Remove secret with the given name
   * @return true when successful, otherwise returns false
   */
  virtual bool removeSecret(const std::string& name) PURE;

};

}  // namespace Secret
}  // namespace Envoy
