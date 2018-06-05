licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "secret_manager_impl_lib",
    srcs = ["secret_manager_impl.cc"],
    hdrs = ["secret_manager_impl.h"],
    deps = [
        ":sds_api_lib",
        "//include/envoy/secret:secret_manager_interface",
        "//include/envoy/server:instance_interface",
        "//source/common/ssl:tls_certificate_config_impl_lib",
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
        "//include/envoy/secret:secret_manager_interface",
        "//include/envoy/server:instance_interface",
        "//source/common/config:resources_lib",
        "//source/common/config:subscription_factory_lib",
        "//source/common/ssl:tls_certificate_config_impl_lib",
    ],
)

envoy_cc_library(
    name = "sds_subscription_lib",
    srcs = ["sds_subscription.cc"],
    hdrs = ["sds_subscription.h"],
    deps = [
        "//include/envoy/config:subscription_interface",
        "//source/common/config:lds_json_lib",
        "//source/common/config:utility_lib",
        "//source/common/http:rest_api_fetcher_lib",
        "//source/common/json:json_validator_lib",
    ],
)
