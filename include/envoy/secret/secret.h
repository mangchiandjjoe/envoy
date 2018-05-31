#pragma once

#include <memory>
#include <string>

#include "envoy/common/pure.h"

#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Secret {

/**
 * An instance of the secret.
 */
class Secret {
public:
  virtual ~Secret() {}

  /**
   * @return a name of the secret.
   */
  virtual const std::string& name() const PURE;
};

typedef std::shared_ptr<Secret> SecretSharedPtr;

} // namespace Secret
} // namespace Envoy
