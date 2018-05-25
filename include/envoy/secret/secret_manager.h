#pragma once

#include <string>

#include "envoy/secret/secret.h"

namespace Envoy {
namespace Secret {

/**
 * A manager for all static secrets.
 *
 * TODO(jaebong) Support dynamic secrets.
 */
class SecretManager {
public:
  virtual ~SecretManager() {}

  /**
   * @param secret Updated Secret.
   */
  virtual void addOrUpdateStaticSecret(SecretSharedPtr secret) PURE;

  /**
   * @return the static secret for the given name.
   */
  virtual const SecretSharedPtr findSecret(const std::string& name) const PURE;
};

} // namespace Secret
} // namespace Envoy
