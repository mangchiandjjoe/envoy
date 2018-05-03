licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()

envoy_cc_test(
    name = "sds_api_test",
    srcs = [
        "sds_api_test.cc",
    ],
    data = [
        "//test/common/secret/test_data:secrets",
    ],
    deps = [
        "//source/common/secret:sds_api_lib",
        "//test/mocks/runtime:runtime_mocks",
        "//test/test_common:environment_lib",
    ],
)

envoy_cc_test(
    name = "secret_impl_test",
    srcs = [
        "secret_impl_test.cc",
    ],
    data = [
        "//test/common/secret/test_data:secrets",
    ],
    deps = [
        "//source/common/secret:secret_impl_lib",
        "//test/mocks/runtime:runtime_mocks",
        "//test/test_common:environment_lib",
    ],
)


