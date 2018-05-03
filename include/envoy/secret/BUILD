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
    name = "secret_manager_interface",
    hdrs = ["secret_manager.h"],
    deps = [
        ":secret_interface",
        "//include/envoy/config:subscription_interface",
        "@envoy_api//envoy/config/bootstrap/v2:bootstrap_cc",
    ]
)
