#pragma once

#include <string>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/secret/secret.h"

namespace Envoy {
namespace Secret {

/**
 * A manager for static secrets.
 *
 * TODO(jaebong) Support dynamic secrets.
 */
class SecretManager {
public:
  virtual ~SecretManager() {}

  /**
   * add or update secret grouped by type.
   * @param secret a shared_ptr of an implementation of Secret.
   */
  virtual void addOrUpdateSecret(const SecretSharedPtr& secret) PURE;

  /**
   * @param name a name of the secret.
   * @return the secret in given type. Returns nullptr if the secret is not found.
   */
  virtual const SecretSharedPtr findSecret(Secret::SecretType type,
                                           const std::string& name) const PURE;

  /**
   * @param secret a protobuf message of envoy::api::v2::auth::Secret.
   * @return SecretSharedPtr instance created from secret configuration.
   * @throws an EnvoyException when secret is not implemented yet.
   */
  virtual const SecretSharedPtr loadSecret(const envoy::api::v2::auth::Secret& secret) const PURE;
};

} // namespace Secret
} // namespace Envoy