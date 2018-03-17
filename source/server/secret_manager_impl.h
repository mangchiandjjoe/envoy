#pragma once

#include <condition_variable>

#include "envoy/server/secret_manager.h"
#include "envoy/server/instance.h"
#include "envoy/server/worker.h"
#include "envoy/ssl/secret.h"
#include "common/ssl/secret_impl.h"

namespace Envoy {
namespace Server {

class SecretManagerImpl : public SecretManager {
 public:
  SecretManagerImpl(Instance& server);

  virtual ~SecretManagerImpl() {
  }

  bool addOrUpdateSecret(const envoy::api::v2::auth::Secret& config) override;

  std::shared_ptr<Ssl::Secret> getSecret(const std::string& name) override;

  SecretInfoMap secrets() override;

  bool removeSecret(const std::string& name) override;

 private:
  const std::string readDataSource(
      const envoy::api::v2::core::DataSource& source, bool allow_empty);

  const std::string getDataSourcePath(
      const envoy::api::v2::core::DataSource& source);

  void readLock();
  void readUnlock();
  void writeLock();
  void writeUnlock();

 private:
  Instance& server_;
  SecretInfoMap secrets_;

 private:
  std::mutex shared_;
  std::condition_variable reader_queue_;
  std::condition_variable writer_queue_;
  int active_readers_;
  int waiting_writers_;
  int active_writers_;
};

}  // namespace Server
}  // namespace Envoy
