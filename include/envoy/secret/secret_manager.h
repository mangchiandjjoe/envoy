#pragma once

#include <string>

#include "envoy/secret/secret.h"

namespace Envoy {
namespace Secret {

/**
 * A manager for all static secrets.
 */
class SecretManager {
public:
  virtual ~SecretManager() {}

  /**
   * @param secret Updated Secret.
   */

  virtual void addOrUpdateStaticSecret(const SecretSharedPtr secret) PURE;

  /**
   * @return the static secret for the given name.
   */
  virtual const SecretSharedPtr staticSecret(const std::string& name) const PURE;
};

} // namespace Secret
} // namespace Envoy
