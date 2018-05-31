#pragma once

#include <fmt/format.h>

#include <memory>
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
  template <typename T> void addOrUpdateSecret(const SecretSharedPtr& secret) {
    addOrUpdateSecret(typeid(T).name(), secret);
  }

  /**
   * @param name a name of the secret
   * @return the secret in given type. Returns nullptr if the secret is not found.
   */
  template <typename T> const std::shared_ptr<T> findSecret(const std::string& name) const {
    auto secret = findSecret(typeid(T).name(), name);
    if (secret == nullptr) {
      return nullptr;
    }

    return std::dynamic_pointer_cast<T>(secret);
  }

private:
  /**
   * Insert or update SecretSharedPtr grouped by type.
   * @param secret Updated Secret.
   */
  virtual void addOrUpdateSecret(const std::string& type, const SecretSharedPtr& secret) PURE;

  /**
   * @return the SecretSharedPtr for the given name and type.
   */
  virtual const SecretSharedPtr findSecret(const std::string& type,
                                           const std::string& name) const PURE;
};

} // namespace Secret
} // namespace Envoy
