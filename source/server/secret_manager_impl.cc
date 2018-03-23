#include "server/secret_manager_impl.h"

#include <string>

#include "openssl/ssl.h"

#include "envoy/config/bootstrap/v2/bootstrap.pb.h"
#include "envoy/server/instance.h"

#include "common/ssl/secret_impl.h"
#include "common/common/assert.h"
#include "common/ssl/context_config_impl.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"
#include "common/config/tls_context_json.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"

namespace Envoy {
namespace Server {

SecretManagerImpl::SecretManagerImpl(
    Instance& server, envoy::config::bootstrap::v2::SecretManager config)
    : server_(server),
      config_(config) {
}

bool SecretManagerImpl::registerSdsConfigSource(const envoy::api::v2::core::ConfigSource& sds_config) {
  std::unique_ptr<SdsApi> sds_api(new SdsApi(
      server_,
      sds_config,
      *this));

  sds_apis_.push_back(std::move(sds_api));

  return true;
}

bool SecretManagerImpl::addOrUpdateSecret(
    const envoy::api::v2::auth::Secret& config) {
  // read/write lock
  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);

  if (config.has_tls_certificate()) {
    std::string certificate_chain = readDataSource(
        config.tls_certificate().certificate_chain(), true);
    std::string private_key = readDataSource(
        config.tls_certificate().private_key(), true);

    secrets_[config.name()] = std::make_shared<Ssl::SecretImpl>(
        Ssl::SecretImpl(certificate_chain, private_key));
  } else if (config.has_session_ticket_keys()) {
    return false;
  } else {
    return false;
  }

  return true;
}

SecretManager::SecretInfoMap SecretManagerImpl::secrets() {
  // read lock
  std::shared_lock < std::shared_timed_mutex > rhs(mutex_);

  SecretManager::SecretInfoMap ret;

  for (const auto secret : secrets_) {
    ret[secret.first] = secret.second;
  }

  return ret;
}

bool SecretManagerImpl::removeSecret(const std::string& name) {
  // read/write lock
  std::unique_lock<std::shared_timed_mutex> lhs(mutex_);

  if (secrets_.find(name) != secrets_.end()) {
    secrets_.erase(name);
  }

  return false;
}

std::shared_ptr<Ssl::Secret> SecretManagerImpl::getSecret(
    const std::string& name) {
  // read lock
  std::shared_lock < std::shared_timed_mutex > rhs(mutex_);

  if (secrets_.find(name) != secrets_.end()) {
    return secrets_[name];
  }

  return nullptr;
}

const std::string SecretManagerImpl::readDataSource(
    const envoy::api::v2::core::DataSource& source, bool allow_empty) {
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
            fmt::format("Unexpected DataSource::specifier_case(): {}",
                        source.specifier_case()));
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

}  // namespace Upstream
}  // namespace Envoy
