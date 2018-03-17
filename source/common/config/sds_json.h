#pragma once

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/json/json_object.h"

namespace Envoy {
namespace Config {

class SdsJson {
 public:
  /**
   */
  static void translateSecret(const Json::Object& json_secret,
                              envoy::api::v2::auth::Secret& secret);
};

}  // namespace Config
}  // namespace Envoy

