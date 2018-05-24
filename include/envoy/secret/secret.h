#pragma once

#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "envoy/common/pure.h"

namespace Envoy {
namespace Secret {

/**
 * Secret contains certificate chain and private key
 */
class Secret {
public:
  virtual ~Secret() {}

  /**
   * @return a name of the SDS secret
   */
  virtual const std::string& name() const PURE;

  /**
   * @return a string of certificate chain
   */
  virtual const std::string& certificateChain() const PURE;

  /**
   * @return a string of private key
   */
  virtual const std::string& privateKey() const PURE;

  /**
   * @return true if the secret is downloaded from the SDS server
   */
  virtual bool fromSDS() const PURE;

  /**
   * @return hash code of SDS config source
   */
  virtual uint64_t configSourceHash() const PURE;
};

typedef std::shared_ptr<Secret> SecretSharedPtr;


/**
 * Callbacks invoked by a secret manager.
 */
class SecretCallbacks {
public:
  virtual ~SecretCallbacks() {}

  virtual void onAddOrUpdateSecret() PURE;
};



} // namespace Secret
} // namespace Envoy
