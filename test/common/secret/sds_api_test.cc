#include <string>
#include <vector>
#include <fstream>
#include <iostream>

#include "source/common/secret/sds_api.h"

#include "test/mocks/runtime/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"
#include "google/protobuf/text_format.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {

namespace {

}  // namespace

class SdsApiTest : public testing::Test {
 public:
  SdsApiTest() : request_(&cluster_manager_.async_client_) {}

  void setup(bool v2_rest = false) {
    v2_rest_ = v2_rest;
    const std::string config_json =
        R"EOF(
    {
      "cluster": "foo_cluster",
      "refresh_delay_ms": 1000
    }
    )EOF";

    Json::ObjectSharedPtr config = Json::Factory::loadFromString(config_json);
    envoy::api::v2::core::ConfigSource lds_config;
    Config::Utility::translateLdsConfig(*config, lds_config);
    if (v2_rest) {
      lds_config.mutable_api_config_source()->set_api_type(
          envoy::api::v2::core::ApiConfigSource::REST);
    }

    Upstream::ClusterManager::ClusterInfoMap cluster_map;
    Upstream::MockCluster cluster;
    cluster_map.emplace("foo_cluster", cluster);
    EXPECT_CALL(cluster_manager_, clusters()).WillOnce(Return(cluster_map));
    EXPECT_CALL(cluster, info());
    EXPECT_CALL(*cluster.info_, addedViaApi());
    EXPECT_CALL(cluster, info());
    EXPECT_CALL(*cluster.info_, type());
    interval_timer_ = new Event::MockTimer(&dispatcher_);
    EXPECT_CALL(init_, registerTarget(_));
    lds_.reset(
        new LdsApi(lds_config, cluster_manager_, dispatcher_, random_, init_, local_info_, store_,
                   listener_manager_));

    expectRequest();
    init_.initialize();
  }

  void expectAdd(const std::string& listener_name, bool updated) {
    EXPECT_CALL(listener_manager_, addOrUpdateListener(_, true)).WillOnce(
        Invoke([listener_name, updated](const envoy::api::v2::Listener& config, bool) -> bool {
          EXPECT_EQ(listener_name, config.name());
          return updated;
        }));
  }

  void expectRequest() {
    EXPECT_CALL(cluster_manager_, httpAsyncClientForCluster("foo_cluster"));
    EXPECT_CALL(cluster_manager_.async_client_, send_(_, _, _)).WillOnce(
        Invoke([&](Http::MessagePtr& request, Http::AsyncClient::Callbacks& callbacks,
            const absl::optional<std::chrono::milliseconds>&) -> Http::AsyncClient::Request* {
          EXPECT_EQ((Http::TestHeaderMapImpl {
                    { ":method", v2_rest_ ? "POST" : "GET"},
                    { ":path", v2_rest_ ? "/v2/discovery:listeners"
                      : "/v1/listeners/cluster_name/node_name"},
                    { ":authority", "foo_cluster"}}),
              request->headers());
          callbacks_ = &callbacks;
          return &request_;
        }));
  }

  void makeListenersAndExpectCall(const std::vector<std::string>& listener_names) {
    std::vector<std::reference_wrapper<Network::ListenerConfig>> refs;
    listeners_.clear();
    for (const auto& name : listener_names) {
      listeners_.emplace_back();
      listeners_.back().name_ = name;
      refs.push_back(listeners_.back());
    }
    EXPECT_CALL(listener_manager_, listeners()).WillOnce(Return(refs));
  }

  bool v2_rest_{};
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  Event::MockDispatcher dispatcher_;
  NiceMock<Runtime::MockRandomGenerator> random_;
  Init::MockManager init_;
  NiceMock<LocalInfo::MockLocalInfo> local_info_;
  Stats::IsolatedStoreImpl store_;
  MockListenerManager listener_manager_;
  Http::MockAsyncClientRequest request_;
  std::unique_ptr<LdsApi> lds_;
  Event::MockTimer* interval_timer_{};
  Http::AsyncClient::Callbacks* callbacks_{};

 private:
  std::list<NiceMock<Network::MockListenerConfig>> listeners_;
};

TEST_F(SdsApiTest, TestSecretInitializationFromProtobuf) {

}

}  // namespace Ssl
}  // namespace Envoy
