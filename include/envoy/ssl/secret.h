#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/common/exception.h"
#include "envoy/network/connection.h"
#include "envoy/network/listen_socket.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context.h"

namespace Envoy {
namespace Ssl {

class SecretConfig {
 public:
  virtual ~SecretConfig() {
  }
};

/**
 *
 */
class Secret {
 public:
  virtual ~Secret() {
  }
  virtual const std::string getCertificateChain() PURE;
  virtual const std::string getPrivateKey() PURE;
};

typedef std::unique_ptr<Secret> SecretPtr;

/**
 * Thrown when there is a runtime error creating/binding a secret.
 */
class CreateSecretException : public EnvoyException {
 public:
  CreateSecretException(const std::string& what)
      : EnvoyException(what) {
  }
};

}  // namespace Network
}  // namespace Envoy
