licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "secret_impl_lib",
    srcs = ["secret_impl.cc"],
    hdrs = ["secret_impl.h"],
    external_deps = ["ssl"],
    deps = [
        "//source/common/ssl:context_config_lib",
        "//source/common/ssl:context_lib",
        "//include/envoy/secret:secret_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:empty_string",
        "//source/common/common:logger_lib",
        "//source/common/http:headers_lib",
    ],
)

envoy_cc_library(
    name = "sds_subscription_lib",
    srcs = ["sds_subscription.cc"],
    hdrs = ["sds_subscription.h"],
    deps = [
        "//include/envoy/config:subscription_interface",
        "//source/common/common:assert_lib",
        "//source/common/config:lds_json_lib",
        "//source/common/config:utility_lib",
        "//source/common/http:rest_api_fetcher_lib",
        "//source/common/json:config_schemas_lib",
        "//source/common/json:json_validator_lib",
        "@envoy_api//envoy/api/v2:lds_cc",
        "@envoy_api//envoy/api/v2:eds_cc",
    ],
)

envoy_cc_library(
    name = "sds_api_lib",
    srcs = ["sds_api.cc"],
    hdrs = ["sds_api.h"],
    deps = [
        ":sds_subscription_lib",
        "//include/envoy/config:subscription_interface",
        "//include/envoy/secret:secret_interface",
        "//include/envoy/server:instance_interface",
        "//include/envoy/init:init_interface",
        "//include/envoy/server:listener_manager_interface",
        "//include/envoy/secret:secret_manager_interface",
        "//source/common/common:cleanup_lib",
        "//source/common/config:resources_lib",
        "//source/common/config:subscription_factory_lib",
        "//source/common/config:utility_lib",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/api/v2:lds_cc",
    ],
)

envoy_cc_library(
    name = "secret_manager_impl_lib",
    srcs = ["secret_manager_impl.cc"],
    hdrs = ["secret_manager_impl.h"],
    deps = [
        ":sds_api_lib",
        ":secret_impl_lib",
        "//include/envoy/config:subscription_interface",
        "//source/common/common:assert_lib",
        "//source/common/config:lds_json_lib",
        "//source/common/config:utility_lib",
        "//include/envoy/server:instance_interface",
        "//include/envoy/secret:secret_manager_interface",
        "//include/envoy/server:worker_interface",
        "//include/envoy/ssl:context_manager_interface",
        "//source/common/http:rest_api_fetcher_lib",
        "//source/common/json:config_schemas_lib",
        "//source/common/json:json_validator_lib",
        "@envoy_api//envoy/api/v2:lds_cc",
    ],
)