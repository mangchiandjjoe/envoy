#pragma once

#include <memory>
#include <string>

#include "envoy/common/pure.h"

namespace Envoy {
namespace Secret {

/**
 * An instance of the TlsCertificateSecret
 */
class TlsCertificateSecret {
public:
  virtual ~TlsCertificateSecret() {}

  /**
   * @return a string of certificate chain
   */
  virtual const std::string& certificateChain() const PURE;

  /**
   * @return a string of private key
   */
  virtual const std::string& privateKey() const PURE;

  /**
   * @return true if secret contains same certificate chain and private key.
   *              Otherwise returns false.
   */
  virtual bool equalTo(const TlsCertificateSecret& secret) const PURE;
};

typedef std::shared_ptr<const TlsCertificateSecret> TlsCertificateSecretSharedPtr;

} // namespace Secret
} // namespace Envoy
