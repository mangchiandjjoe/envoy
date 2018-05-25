#pragma once

#include <memory>
#include <string>

#include "envoy/common/pure.h"

#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Secret {

/**
 * Secret contains certificate chain and private key.
 */
class Secret {
public:
  virtual ~Secret() {}

  /**
   * @return protobuf message that generates the secret.
   */
  virtual const Protobuf::Message& message() const PURE;

  /**
   * @return a name of the secret.
   */
  virtual const std::string& name() const PURE;
};

typedef std::shared_ptr<Secret> SecretSharedPtr;

} // namespace Secret
} // namespace Envoy
