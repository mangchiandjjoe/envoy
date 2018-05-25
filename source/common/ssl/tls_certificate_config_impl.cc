#include "common/ssl/tls_certificate_config_impl.h"

#include "common/config/datasource.h"

namespace Envoy {
namespace Ssl {

TlsCertificateConfigImpl::TlsCertificateConfigImpl(const envoy::api::v2::auth::Secret& config)
    : message_([&config] {
        envoy::api::v2::auth::Secret message;
        message.CopyFrom(config);
        return message;
      }()),
      name_(config.name()), certificate_chain_(Config::DataSource::read(
                                config.tls_certificate().certificate_chain(), true)),
      private_key_(Config::DataSource::read(config.tls_certificate().private_key(), true)) {}

} // namespace Ssl
} // namespace Envoy
