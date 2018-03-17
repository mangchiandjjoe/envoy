#include "source/common/config/sds_json.h"

#include "common/common/assert.h"
#include "common/config/address_json.h"
#include "common/config/json_utility.h"
#include "common/config/tls_context_json.h"
#include "common/config/utility.h"
#include "common/config/well_known_names.h"
#include "common/json/config_schemas.h"
#include "common/network/utility.h"

namespace Envoy {
namespace Config {

void SdsJson::translateSecret(const Json::Object& json_secret,
                              envoy::api::v2::auth::Secret& secret) {

  json_secret.validateSchema(Json::Schema::SDS_SCHEMA);

  // TODO(jaebong) implement

  const std::string name = json_secret.getString("name", "");

  if (json_secret.hasObject("tls_certificate")) {
    auto tls_certificate = json_secret.getObject("tls_certificate");

    auto mutable_tls_certificate = secret.mutable_tls_certificate();
    if (tls_certificate->hasObject("certificate_chain")) {
      auto certificate_chain = tls_certificate->getObject("certificate_chain");
      auto mutable_certificate_chain = mutable_tls_certificate
          ->mutable_certificate_chain();

      if (certificate_chain->hasObject("filename")) {
        mutable_certificate_chain->set_filename(
            certificate_chain->getString("filename"));
      } else if (certificate_chain->hasObject("inline_bytes")) {
        mutable_certificate_chain->set_inline_bytes(certificate_chain->getString("inline_bytes"));
      } else if (certificate_chain->hasObject("inline_string")) {

      }

    }

    if (tls_certificate->hasObject("private_key")) {
      // error
    }

  } else if (json_secret.hasObject("session_ticket_keys")) {

  } else {

  }
}

}  // namespace Upstream
}  // namespace Envoy
