#include "common/ssl/secret_impl.h"

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
namespace Ssl {

SecretImpl::SecretImpl(const std::string& certificate_chain,
                       const std::string& private_key)
    : certificate_chain_(certificate_chain),
      private_key_(private_key) {

}

}  // namespace Upstream
}  // namespace Envoy