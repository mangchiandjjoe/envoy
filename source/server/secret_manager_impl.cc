#include "server/secret_manager_impl.h"
#include "envoy/server/instance.h"
#include "common/ssl/secret_impl.h"

#include <string>

#include "common/common/assert.h"
#include "common/ssl/context_config_impl.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"
#include "common/config/tls_context_json.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Server {

SecretManagerImpl::SecretManagerImpl(Instance& server)
    : server_(server),
      shared_(),
      reader_queue_(),
      writer_queue_(),
      active_readers_(0),
      waiting_writers_(0),
      active_writers_(0) {

}

bool SecretManagerImpl::addOrUpdateSecret(
    const envoy::api::v2::auth::Secret& config) {

//  readLock();
//  writeLock();
  std::cout << __FILE__ << ":" << __LINE__ << " " << std::endl;

  if (config.has_tls_certificate()) {
    std::string certificate_chain = readDataSource(
        config.tls_certificate().certificate_chain(), true);
    std::cout << __FILE__ << ":" << __LINE__ << " " << certificate_chain << std::endl;
    std::string private_key = readDataSource(
        config.tls_certificate().private_key(), true);
    std::cout << __FILE__ << ":" << __LINE__ << " " << private_key << std::endl;

    secrets_[config.name()] = std::make_shared<Ssl::SecretImpl>(
        Ssl::SecretImpl(certificate_chain, private_key));
  } else if (config.has_session_ticket_keys()) {
    return false;
  } else {
    return false;
  }

//  writeUnlock();
//  readUnlock();

  return true;
}

SecretManager::SecretInfoMap SecretManagerImpl::secrets() {
//  readLock();

  SecretManager::SecretInfoMap ret;

  for (const auto secret : secrets_) {
    ret[secret.first] = secret.second;
  }

  //readUnlock();

  return ret;
}

bool SecretManagerImpl::removeSecret(const std::string& name) {
//  readLock();
//  writeLock();

  if (secrets_.find(name) != secrets_.end()) {
    secrets_.erase(name);
  }

//  writeUnlock();
//  readUnlock();

  return false;
}

std::shared_ptr<Ssl::Secret> SecretManagerImpl::getSecret(
    const std::string& name) {
//  readLock();

  if (secrets_.find(name) != secrets_.end()) {
    return secrets_[name];
  }

  //readUnlock();

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

void SecretManagerImpl::readLock() {
  std::unique_lock<std::mutex> lk(shared_);
  while (waiting_writers_ != 0) {
    reader_queue_.wait(lk);
  }
  ++active_readers_;
  lk.unlock();
}

void SecretManagerImpl::readUnlock() {
  std::unique_lock<std::mutex> lk(shared_);
  --active_readers_;
  lk.unlock();
  writer_queue_.notify_one();
}

void SecretManagerImpl::writeLock() {
  std::unique_lock<std::mutex> lk(shared_);
  ++waiting_writers_;
  while (active_readers_ != 0 || active_writers_ != 0) {
    writer_queue_.wait(lk);
  }
  ++active_writers_;
  lk.unlock();
}

void SecretManagerImpl::writeUnlock() {
  std::unique_lock<std::mutex> lk(shared_);
  --waiting_writers_;
  --active_writers_;
  if (waiting_writers_ > 0) {
    writer_queue_.notify_one();
  } else {
    reader_queue_.notify_all();
  }
  lk.unlock();
}

}  // namespace Upstream
}  // namespace Envoy
