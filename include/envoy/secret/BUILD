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
    deps = [
        "//source/common/protobuf",
    ],
)

envoy_cc_library(
    name = "secret_manager_interface",
    hdrs = ["secret_manager.h"],
    deps = [
        ":secret_interface",
    ],
)
