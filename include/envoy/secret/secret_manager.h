#pragma once

#include <string>

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
   * @param name a name of the secret
   * @return the secret in given type. Returns nullptr if the secret is not found.
   */
  virtual const SecretSharedPtr findSecret(Secret::SecretType type,
                                           const std::string& name) const PURE;
};

} // namespace Secret
} // namespace Envoy
