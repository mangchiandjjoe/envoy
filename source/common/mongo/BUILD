package(default_visibility = ["//visibility:public"])

load("//bazel:envoy_build_system.bzl", "envoy_cc_library")

envoy_cc_library(
    name = "bson_lib",
    srcs = ["bson_impl.cc"],
    hdrs = ["bson_impl.h"],
    deps = [
        "//include/envoy/buffer:buffer_includes",
        "//include/envoy/mongo:bson_includes",
        "//source/common/common:assert_lib",
        "//source/common/common:hex_lib",
        "//source/common/common:logger_lib",
    ],
)

envoy_cc_library(
    name = "codec_lib",
    srcs = ["codec_impl.cc"],
    hdrs = ["codec_impl.h"],
    deps = [
        ":bson_lib",
        "//include/envoy/buffer:buffer_includes",
        "//include/envoy/mongo:codec_includes",
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:logger_lib",
    ],
)

envoy_cc_library(
    name = "proxy_lib",
    srcs = ["proxy.cc"],
    hdrs = ["proxy.h"],
    deps = [
        ":codec_lib",
        ":utility_lib",
        "//include/envoy/access_log:access_log_includes",
        "//include/envoy/common:time_includes",
        "//include/envoy/filesystem:filesystem_includes",
        "//include/envoy/mongo:codec_includes",
        "//include/envoy/network:connection_includes",
        "//include/envoy/network:filter_includes",
        "//include/envoy/runtime:runtime_includes",
        "//include/envoy/stats:stats_includes",
        "//include/envoy/stats:stats_macros",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:assert_lib",
        "//source/common/common:logger_lib",
        "//source/common/common:utility_lib",
        "//source/common/network:filter_lib",
    ],
)

envoy_cc_library(
    name = "utility_lib",
    srcs = ["utility.cc"],
    hdrs = ["utility.h"],
    deps = [
        "//include/envoy/mongo:codec_includes",
        "//source/common/json:json_loader_lib",
    ],
)