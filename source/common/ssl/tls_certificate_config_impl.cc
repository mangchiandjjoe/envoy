#include "common/ssl/tls_certificate_config_impl.h"

#include "envoy/common/exception.h"

#include "common/config/datasource.h"

namespace Envoy {
namespace Ssl {

namespace {

const std::string readTlsCertificateCertificateChain(const envoy::api::v2::auth::Secret& config) {
  if (!config.has_tls_certificate()) {
    throw EnvoyException("Secret does not have the tls_certificate");
  }

  return Config::DataSource::read(config.tls_certificate().certificate_chain(), true);
}

const std::string readTlsCertificatePrivateKey(const envoy::api::v2::auth::Secret& config) {
  if (!config.has_tls_certificate()) {
    throw EnvoyException("Secret does not have the tls_certificate");
  }

  return Config::DataSource::read(config.tls_certificate().private_key(), true);
}

} // namespace

TlsCertificateConfigImpl::TlsCertificateConfigImpl(const envoy::api::v2::auth::Secret& config)
    : name_(config.name()), certificate_chain_(readTlsCertificateCertificateChain(config)),
      private_key_(readTlsCertificatePrivateKey(config)) {}

} // namespace Ssl
} // namespace Envoy
