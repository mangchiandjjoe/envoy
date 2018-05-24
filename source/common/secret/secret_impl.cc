#include "common/secret/secret_impl.h"

#include <string>

#include "common/common/assert.h"
#include "common/config/datasource.h"

namespace Envoy {
namespace Secret {

SecretImpl::SecretImpl(const envoy::api::v2::auth::Secret& config, const bool from_sds,
                       const uint64_t config_source_hash)
    : name_(config.name()),
      certificate_chain_(
          Config::DataSource::read(config.tls_certificate().certificate_chain(), true)),
      private_key_(Config::DataSource::read(config.tls_certificate().private_key(), true)),
      from_sds_(from_sds),
      config_source_hash_(config_source_hash) {
}

}  // namespace Secret
}  // namespace Envoy
