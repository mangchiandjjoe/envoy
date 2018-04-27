#pragma once

#include <envoy/secret/secret.h>
#include <unordered_map>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"
#include "envoy/network/transport_socket.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Server {

/**
 * A manager for all secrets and all threaded connection handling workers.
 */
class SecretManager {
 public:
  virtual ~SecretManager() {
  }

  virtual bool addOrUpdateSecret(const envoy::api::v2::auth::Secret& config, bool is_static) PURE;

  typedef std::unordered_map<std::string, std::shared_ptr<Ssl::Secret>> SecretInfoMap;

  virtual SecretInfoMap secrets() PURE;

  virtual std::shared_ptr<Ssl::Secret> getSecret(const std::string& name, bool is_static) PURE;

  virtual bool removeSecret(const std::string& name) PURE;

  virtual bool addOrUpdateSdsConfigSource(const envoy::api::v2::core::ConfigSource& config_source) PURE;

};

}  // namespace Server
}  // namespace Envoy
