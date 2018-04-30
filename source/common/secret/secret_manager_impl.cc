#include "common/secret/secret_manager_impl.h"

#include <string>
#include <shared_mutex>

#include "openssl/ssl.h"

#include "envoy/config/bootstrap/v2/bootstrap.pb.h"
#include "envoy/api/v2/auth/cert.pb.h"

#include "envoy/server/instance.h"

#include "common/common/assert.h"
#include "common/common/logger.h"
#include "common/secret/secret_impl.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"
#include "common/config/tls_context_json.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"
#include "common/common/logger.h"

namespace Envoy {
namespace Secret {

SecretManagerImpl::SecretManagerImpl(Server::Instance& server,
                                     envoy::config::bootstrap::v2::SecretManager config)
    : server_(server),
      config_(config) {
}

bool SecretManagerImpl::addOrUpdateSdsConfigSource(
    const envoy::api::v2::core::ConfigSource& sds_config) {
  std::size_t hash = MessageUtil::hash(sds_config);
  if (sds_apis_.find(hash) != sds_apis_.end()) {
    return true;
  }

  std::unique_ptr<SdsApi> sds_api(new SdsApi(server_, sds_config, *this));
  sds_apis_[hash] = std::move(sds_api);

  return true;
}

bool SecretManagerImpl::addOrUpdateSecret(const envoy::api::v2::auth::Secret& config,
                                          bool is_static) {
  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);

  switch (config.type_case()) {
    case envoy::api::v2::auth::Secret::kTlsCertificate:
      {
        auto secret = SecretPtr(new SecretImpl(config, is_static));

        if (secrets_.find(config.name()) != secrets_.end()) {
          if (secrets_[config.name()]->getCertificateChain() == secret->getCertificateChain()
              && secrets_[config.name()]->getPrivateKey() == secret->getPrivateKey()) {
            // Certificate chain and private key are same as locally cached. No need to update
            ENVOY_LOG(debug, "sds: no need to update '{}' skipped", config.name());
            return false;
          }
        }

        auto old_secret = secrets_[config.name()];
        secrets_[config.name()] = secret;

        if (&server_.clusterManager() != nullptr && &server_.listenerManager() != nullptr) {
          // Create pending cluster or update secret
          if (!server_.clusterManager().sdsSecretUpdated(config.name())) {
            // In case of failure, revert back to the previous secret
            secrets_[config.name()] = old_secret;
            return false;
          }

          // Create pending listener or update secret
          if (!server_.listenerManager().sdsSecretUpdated(config.name())) {
            // In case of failure, revert back to the previous secret
            secrets_[config.name()] = old_secret;
            return false;
          }
        }
      }
      break;
    case envoy::api::v2::auth::Secret::kSessionTicketKeys:
      NOT_IMPLEMENTED;
    default:
      ENVOY_LOG(error, "sds: no need to update '{}' skipped", config.name());
      return false;
  }

  return true;
}

bool SecretManagerImpl::removeSecret(const std::string& name) {
  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);

  if (secrets_.find(name) != secrets_.end()) {
    secrets_.erase(name);
  }

  return false;
}

SecretPtr SecretManagerImpl::getSecret(const std::string& name, bool is_static) {
  if (secrets_.find(name) != secrets_.end()) {
    return secrets_[name]->isStatic() == is_static ? secrets_[name] : nullptr;
  }

  return nullptr;
}

const std::string SecretManagerImpl::readDataSource(const envoy::api::v2::core::DataSource& source,
                                                    bool allow_empty) {
  switch (source.specifier_case()) {
    case envoy::api::v2::core::DataSource::kFilename:
      return Filesystem::fileReadToEnd(source.filename());
    case envoy::api::v2::core::DataSource::kInlineBytes:
      return source.inline_bytes();
    case envoy::api::v2::core::DataSource::kInlineString:
      return source.inline_string();
    default:
      if (!allow_empty) {
        throw EnvoyException(
            fmt::format("Unexpected DataSource::specifier_case(): {}", source.specifier_case()));
      }
      return "";
  }
}

const std::string SecretManagerImpl::getDataSourcePath(
    const envoy::api::v2::core::DataSource& source) {
  return
      source.specifier_case() == envoy::api::v2::core::DataSource::kFilename ?
          source.filename() : "";
}

}  // namespace Secret
}  // namespace Envoy
