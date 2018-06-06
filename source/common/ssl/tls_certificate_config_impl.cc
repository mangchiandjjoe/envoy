#include "common/ssl/tls_certificate_config_impl.h"

#include <memory>

#include "common/config/datasource.h"

namespace Envoy {
namespace Ssl {

TlsCertificateConfigImpl::TlsCertificateConfigImpl(const envoy::api::v2::auth::Secret& config)
    : message_(config), name_(config.name()),
      certificate_chain_(
          Config::DataSource::read(config.tls_certificate().certificate_chain(), true)),
      private_key_(Config::DataSource::read(config.tls_certificate().private_key(), true)),
      type_(Secret::TLS_CERTIFICATE) {}

bool TlsCertificateConfigImpl::equalTo(const Envoy::Secret::SecretSharedPtr& secret) const {
  if (type_ != secret->type()) {
    return false;
  }

  auto target = std::dynamic_pointer_cast<Ssl::TlsCertificateConfigImpl>(secret);
  if (!target) {
    return false;
  }

  return certificate_chain_ == target->certificateChain() && private_key_ == target->privateKey();
}

} // namespace Ssl
} // namespace Envoy
