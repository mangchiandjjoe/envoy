#include "server/config/network/ssl_socket.h"

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/api/v2/auth/cert.pb.validate.h"
#include "envoy/registry/registry.h"

#include "common/protobuf/utility.h"
#include "common/ssl/context_config_impl.h"
#include "common/ssl/ssl_socket.h"

#include "envoy/server/secret_manager.h"

namespace Envoy {
namespace Server {
namespace Configuration {

Network::TransportSocketFactoryPtr
UpstreamSslSocketFactory::createTransportSocketFactory(const Protobuf::Message& message,
                                                       TransportSocketFactoryContext& context,
                                                       Server::SecretManager& secret_manager) {
  auto config = Ssl::ClientContextConfigImpl(
      MessageUtil::downcastAndValidate<
          const envoy::api::v2::auth::UpstreamTlsContext&>(message),
      secret_manager);

  auto clientSslSocketFactory = std::make_unique<Ssl::ClientSslSocketFactory>(
      config,
      context.sslContextManager(),
      context.statsScope());

  // TODO(jaebong)
  if (config.sdsSecretName().length() > 0) {

  }

  return std::move(clientSslSocketFactory);
}

ProtobufTypes::MessagePtr UpstreamSslSocketFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::api::v2::auth::UpstreamTlsContext>();
}

static Registry::RegisterFactory<UpstreamSslSocketFactory, UpstreamTransportSocketConfigFactory>
    upstream_registered_;

Network::TransportSocketFactoryPtr DownstreamSslSocketFactory::createTransportSocketFactory(
    const std::string& listener_name,
    const std::vector<std::string>& server_names,
    bool skip_context_update,
    const Protobuf::Message& message,
    TransportSocketFactoryContext& context,
    Server::SecretManager& secret_manager) {

  auto serverContextConfigImpl = Ssl::ServerContextConfigImpl(
      MessageUtil::downcastAndValidate<
          const envoy::api::v2::auth::DownstreamTlsContext&>(message),
      secret_manager);

  auto serverSslSocketFactory = std::make_unique<Ssl::ServerSslSocketFactory>(
      serverContextConfigImpl, listener_name, server_names, skip_context_update,
      context.sslContextManager(), context.statsScope());

  return std::move(serverSslSocketFactory);
}

ProtobufTypes::MessagePtr DownstreamSslSocketFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::api::v2::auth::DownstreamTlsContext>();
}

static Registry::RegisterFactory<DownstreamSslSocketFactory, DownstreamTransportSocketConfigFactory>
    downstream_registered_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy
