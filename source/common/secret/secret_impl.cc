#include "common/secret/secret_impl.h"

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
namespace Secret {

SecretImpl::SecretImpl(const envoy::api::v2::auth::Secret& config, bool is_static)
    : name_(config.name()),
      certificate_chain_(readDataSource(config.tls_certificate().certificate_chain(), true)),
      private_key_(readDataSource(config.tls_certificate().private_key(), true)),
      is_static_(is_static) {
}

const std::string SecretImpl::readDataSource(const envoy::api::v2::core::DataSource& source,
                                             bool allow_empty) {
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
            fmt::format("Unexpected DataSource::specifier_case(): {}", source.specifier_case()));
      }
      return "";
  }
}

}  // namespace Secret
}  // namespace Envoy
