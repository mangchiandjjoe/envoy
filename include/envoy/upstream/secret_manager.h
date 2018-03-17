#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include "envoy/access_log/access_log.h"
#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/config/bootstrap/v2/bootstrap.pb.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/http/async_client.h"
#include "envoy/http/conn_pool.h"
#include "envoy/local_info/local_info.h"
#include "envoy/runtime/runtime.h"
#include "envoy/upstream/load_balancer.h"
#include "envoy/upstream/thread_local_cluster.h"
#include "envoy/upstream/upstream.h"
#include "envoy/api/v2/auth/cert.pb.h"

//#include "envoy/ssl/secret.h"


namespace Envoy {
namespace Upstream {

/**
 * Manages secrets those can be uniquely referred to.
 */
class SecretManager {
 public:
  virtual ~SecretManager() {
  }


  /**
   * Add or update a secret via API. The semantics of this API are:
   * 1) The hash of the config is used to determine if an already existing secret has changed.
   *    Nothing is done if the hash matches the previously running configuration.
   * 2) Statically defined secrets (those present when Envoy starts) can not be updated via API.
   *
   * @return true if the action results in an add/update of a secret.
   */
  virtual bool addOrUpdateSecret(
      const envoy::api::v2::auth::Secret& secret) PURE;


  /**
   *
   */
  virtual bool removeSecret(const std::string& name) PURE;


  /**
   * Set a callback that will be invoked when all owned secrets have been initialized.
   */
  virtual void setInitializedCb(std::function<void()> callback) PURE;

  typedef std::unordered_map<std::string,
      std::reference_wrapper<const envoy::api::v2::auth::Secret>> SecretInfoMap;


  /**
   * @return SecretInfoMap returns all current secrets.
   */
  virtual SecretInfoMap secrets() PURE;

  /**
   * Shutdown the secret manager prior to destroying connection pools and other thread local data.
   */
  virtual void shutdown() PURE;


  virtual Http::AsyncClient& httpAsyncClientForCluster(const std::string& cluster) PURE;
};

typedef std::unique_ptr<SecretManager> SecretManagerPtr;

/**
 * Abstract interface for a SDS API provider.
 */
class SdsApi {
 public:
  virtual ~SdsApi() {
  }

  /**
   * Start the first fetch of SDS data.
   */
  virtual void initialize() PURE;

  /**
   * Set a callback that will be called when the SDS API has done an initial load from the remote
   * server. If the initial load fails, the callback will also be called.
   */
  virtual void setInitializedCb(std::function<void()> callback) PURE;

  /**
   * @return std::string last accepted version from fetch.
   *
   * TODO(dnoe): This would ideally return by reference, but this causes a
   *             problem due to incompatible string implementations returned by
   *             protobuf generated code. Revisit when string implementations
   *             are converged.
   */
  virtual const std::string versionInfo() const PURE;
};

typedef std::unique_ptr<SdsApi> SdsApiPtr;

/**
 * Factory for objects needed during Secret manager operation.
 */
class SecretManagerFactory {
 public:
  virtual ~SecretManagerFactory() {
  }

  /**
   * Allocate a Secret manager from configuration proto.
   */
  virtual SecretManagerPtr
  SecretManagerFromProto(
      const envoy::config::bootstrap::v2::Bootstrap& bootstrap,
      Stats::Store& stats, ThreadLocal::Instance& tls, Runtime::Loader& runtime,
      Runtime::RandomGenerator& random, const LocalInfo::LocalInfo& local_info,
      AccessLog::AccessLogManager& log_manager) PURE;

  /**
   * Allocate an HTTP connection pool for the host. Pools are separated by 'priority',
   * 'protocol', and 'options->hashKey()', if any.
   */
  virtual Http::ConnectionPool::InstancePtr
  allocateConnPool(Event::Dispatcher& dispatcher, HostConstSharedPtr host,
                   ResourcePriority priority, Http::Protocol protocol,
                   const Network::ConnectionSocket::OptionsSharedPtr& options)
                       PURE;

  /**
   * Allocate a Secret from configuration proto.
   */
  virtual SecretSharedPtr SecretFromProto(
      const envoy::api::v2::auth::Secret& Secret, SecretManager& cm,
      Outlier::EventLoggerSharedPtr outlier_event_logger, bool added_via_api)
          PURE;

  /**
   * Create a SDS API provider from configuration proto.
   */
  virtual SdsApiPtr createSds(
      const envoy::api::v2::core::ConfigSource& cds_config,
      const Optional<envoy::api::v2::core::ConfigSource>& eds_config,
      SecretManager& cm) PURE;
};

}
}
