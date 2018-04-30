#pragma once

#include <string>
#include <unordered_map>

#include "envoy/ssl/context.h"

namespace Envoy {
namespace Secret {

/**
 * Secret contains certificate chain and private key
 */
class Secret {
 public:
  virtual ~Secret() {
  }

  /**
   * @return a string of certificate chain
   */
  virtual const std::string getCertificateChain() PURE;
  /**
   * @return a string of private key
   */
  virtual const std::string getPrivateKey() PURE;
  /**
   * @return true if the secret is static, otherwise returns false
   */
  virtual bool isStatic() PURE;
};

typedef std::shared_ptr<Secret> SecretPtr;

typedef std::unordered_map<std::string, SecretPtr> SecretInfoMap;

}  // namespace Secret
}  // namespace Envoy
