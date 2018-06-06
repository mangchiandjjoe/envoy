#pragma once

#include <memory>
#include <string>

#include "envoy/common/pure.h"

namespace Envoy {
namespace Secret {

class Secret;

typedef std::shared_ptr<Secret> SecretSharedPtr;

/**
 * An instance of the secret.
 */
class Secret {
public:
  virtual ~Secret() {}

  enum SecretType { TLS_CERTIFICATE };

  /**
   * @return a name of the secret.
   */
  virtual const std::string& name() const PURE;

  /**
   * @return a type of the secret instance.
   */
  virtual SecretType type() const PURE;

  /**
   * @return true if secret contains same values. Otherwise returns false.
   */
  virtual bool equalTo(const SecretSharedPtr& secret) const PURE;
};

} // namespace Secret
} // namespace Envoy
