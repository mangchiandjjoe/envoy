#pragma once

#include <shared_mutex>
#include <unordered_map>
#include <vector>

#include "envoy/secret/secret.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/server/instance.h"

#include "common/secret/sds_api.h"

namespace Envoy {
namespace Secret {

class SecretManagerImpl : public SecretManager {
public:
  SecretManagerImpl(Server::Instance& server) : server_(server) {}

  void addOrUpdateSecret(const std::string& config_source_hash,
                         const envoy::api::v2::auth::Secret& secret) override;
  std::string
  addOrUpdateSdsService(const envoy::api::v2::core::ConfigSource& config_source) override;

  const TlsCertificateSecretSharedPtr
  findTlsCertificateSecret(const std::string& config_source_hash,
                           const std::string& name) const override;

  void registerTlsCertificateSecretCallbacks(const std::string& config_source_hash,
                                             const std::string& secret_name,
                                             SecretCallbacks& callback) override;

protected:
  /**
   * Run registered callback functions for the given type of secret
   */
  template <typename T>
  void runSecretUpdateCallbacksIfAny(
      Event::Dispatcher& dispatcher, std::shared_timed_mutex& secret_update_callbacks_mutex,
      std::unordered_map<
          std::string,
          std::unordered_map<std::string, std::pair<T, std::vector<SecretCallbacks*>>>>&
          registered_callbacks,
      const std::string& config_source_hash, const T& secret);

private:
  Server::Instance& server_;

  // map hash code of SDS config source and SdsApi object
  std::unordered_map<std::string, std::unique_ptr<SdsApi>> sds_apis_;
  mutable std::shared_timed_mutex sds_api_mutex_;

  // Manages pairs of name and TlsCertificateSecret grouped by SDS config source. If SDS config
  // source hash is empty, it is a static secret.
  std::unordered_map<std::string, std::unordered_map<std::string, TlsCertificateSecretSharedPtr>>
      tls_certificate_secrets_;
  mutable std::shared_timed_mutex tls_certificate_secrets_mutex_;

  // callback functions for secret update
  // "config source hash": {
  //   "secret name":
  //      secret,
  //      [{callback}]
  //   ]
  // }
  std::unordered_map<std::string,
                     std::unordered_map<std::string, std::pair<TlsCertificateSecretSharedPtr,
                                                               std::vector<SecretCallbacks*>>>>
      tls_certificate_secret_update_callbacks_;
  mutable std::shared_timed_mutex tls_certificate_secret_update_callbacks_mutex_;
};

} // namespace Secret
} // namespace Envoy
