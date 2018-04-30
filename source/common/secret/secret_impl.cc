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

SecretImpl::SecretImpl(const std::string& certificate_chain,
                       const std::string& private_key, bool is_static)
    : certificate_chain_(certificate_chain),
      private_key_(private_key),
      is_static_(is_static) {

}

}  // namespace Secret
}  // namespace Envoy
