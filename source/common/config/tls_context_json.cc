#include "common/config/tls_context_json.h"

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/api/v2/auth/cert.pb.validate.h"
#include "envoy/json/json_object.h"

#include "common/common/utility.h"
#include "common/config/json_utility.h"
#include "common/config/utility.h"
#include "common/protobuf/utility.h"


namespace Envoy {
namespace Config {

void TlsContextJson::translateDownstreamTlsContext(
    const Json::Object& json_tls_context,
    envoy::api::v2::auth::DownstreamTlsContext& downstream_tls_context) {
  translateCommonTlsContext(json_tls_context, *downstream_tls_context.mutable_common_tls_context());
  JSON_UTIL_SET_BOOL(json_tls_context, downstream_tls_context, require_client_certificate);

  const std::vector<std::string> paths =
      json_tls_context.getStringArray("session_ticket_key_paths", true);
  for (const std::string& path : paths) {
    downstream_tls_context.mutable_session_ticket_keys()->mutable_keys()->Add()->set_filename(path);
  }
  MessageUtil::validate(downstream_tls_context);
}

void TlsContextJson::translateUpstreamTlsContext(
    const Json::Object& json_tls_context,
    envoy::api::v2::auth::UpstreamTlsContext& upstream_tls_context) {
  translateCommonTlsContext(json_tls_context, *upstream_tls_context.mutable_common_tls_context());
  upstream_tls_context.set_sni(json_tls_context.getString("sni", ""));
  MessageUtil::validate(upstream_tls_context);
}

void TlsContextJson::translateCommonTlsContext(
    const Json::Object& json_tls_context,
    envoy::api::v2::auth::CommonTlsContext& common_tls_context) {
  const std::string alpn_protocols_str{json_tls_context.getString("alpn_protocols", "")};
  for (auto alpn_protocol : StringUtil::splitToken(alpn_protocols_str, ",")) {
    common_tls_context.add_alpn_protocols(std::string{alpn_protocol});
  }

  common_tls_context.mutable_deprecated_v1()->set_alt_alpn_protocols(
      json_tls_context.getString("alt_alpn_protocols", ""));

  translateTlsCertificate(json_tls_context, *common_tls_context.mutable_tls_certificates()->Add());

  if(json_tls_context.hasObject("tls_certificate_sds_secret_configs")) {
    for(auto node: json_tls_context.getObjectArray("tls_certificate_sds_secret_configs")) {
      auto sds_secret_configs = common_tls_context.mutable_tls_certificate_sds_secret_configs()->Add();
      sds_secret_configs->set_name(node->getString("name"));
      if(node->hasObject("sds_config")) {
        translateConfigSource(*node->getObject("sds_config"), *sds_secret_configs->mutable_sds_config());
      }
    }
  }

  auto* validation_context = common_tls_context.mutable_validation_context();
  if (json_tls_context.hasObject("ca_cert_file")) {
    validation_context->mutable_trusted_ca()->set_filename(
        json_tls_context.getString("ca_cert_file", ""));
  }
  if (json_tls_context.hasObject("crl_file")) {
    validation_context->mutable_crl()->set_filename(json_tls_context.getString("crl_file", ""));
  }
  if (json_tls_context.hasObject("verify_certificate_hash")) {
    validation_context->add_verify_certificate_hash(
        json_tls_context.getString("verify_certificate_hash"));
  }
  for (const auto& san : json_tls_context.getStringArray("verify_subject_alt_name", true)) {
    validation_context->add_verify_subject_alt_name(san);
  }

  const std::string cipher_suites_str{json_tls_context.getString("cipher_suites", "")};
  for (auto cipher_suite : StringUtil::splitToken(cipher_suites_str, ":")) {
    common_tls_context.mutable_tls_params()->add_cipher_suites(std::string{cipher_suite});
  }

  const std::string ecdh_curves_str{json_tls_context.getString("ecdh_curves", "")};
  for (auto ecdh_curve : StringUtil::splitToken(ecdh_curves_str, ":")) {
    common_tls_context.mutable_tls_params()->add_ecdh_curves(std::string{ecdh_curve});
  }
}

void TlsContextJson::translateTlsCertificate(
    const Json::Object& json_tls_context, envoy::api::v2::auth::TlsCertificate& tls_certificate) {
  if (json_tls_context.hasObject("cert_chain_file")) {
    tls_certificate.mutable_certificate_chain()->set_filename(
        json_tls_context.getString("cert_chain_file", ""));
  }
  if (json_tls_context.hasObject("private_key_file")) {
    tls_certificate.mutable_private_key()->set_filename(
        json_tls_context.getString("private_key_file", ""));
  }
}



void TlsContextJson::translateConfigSource(
    const Json::Object& json_config_source,
    envoy::api::v2::core::ConfigSource& config_source) {
  //json_config_source.validateSchema(Json::Schema::...);

  if (json_config_source.getString("path").length() > 0) {
    config_source.set_path(json_config_source.getString("path"));
  } else if (json_config_source.hasObject("api_config_source")) {
    Utility::translateApiConfigSource(json_config_source.getObject("api_config_source")->getString("name"),
                             json_config_source.getObject("api_config_source")->getInteger("refresh_delay_ms", 30000),
                             json_config_source.getObject("api_config_source")->getString("api_type", ApiType::get().RestLegacy),
                             *config_source.mutable_api_config_source());
  } else if (json_config_source.getObject("ads")) {
    // AggregatedConfigSource is empty
  } else {
    throw EnvoyException("ConfigSource should be one of path, api_config_source or ads");
  }
}

} // namespace Config
} // namespace Envoy
