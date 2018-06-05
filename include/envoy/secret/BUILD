licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "secret_interface",
    hdrs = ["secret.h"],
)

envoy_cc_library(
    name = "secret_callbacks_interface",
    hdrs = ["secret_callbacks.h"],
)

envoy_cc_library(
    name = "secret_manager_interface",
    hdrs = ["secret_manager.h"],
    deps = [
        ":secret_callbacks_interface",
        ":secret_interface",
        "@envoy_api//envoy/api/v2/auth:cert_cc",
        "@envoy_api//envoy/api/v2/core:config_source_cc",
    ],
)
