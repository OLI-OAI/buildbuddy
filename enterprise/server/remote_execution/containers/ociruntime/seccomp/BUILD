load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(default_visibility = ["//enterprise:__subpackages__"])

go_library(
    name = "seccomp",
    srcs = ["seccomp.go"],
    embedsrcs = select({
        "@io_bazel_rules_go//go/platform:android": [
            "seccomp.json",
        ],
        "@io_bazel_rules_go//go/platform:linux": [
            "seccomp.json",
        ],
        "//conditions:default": [],
    }),
    importpath = "github.com/buildbuddy-io/buildbuddy/enterprise/server/remote_execution/containers/ociruntime/seccomp",
    target_compatible_with = ["@platforms//os:linux"],
    deps = select({
        "@io_bazel_rules_go//go/platform:android": [
            "@com_github_moby_profiles_seccomp//:seccomp",
            "@com_github_opencontainers_runtime_spec//specs-go",
            "@org_golang_x_sys//unix",
        ],
        "@io_bazel_rules_go//go/platform:linux": [
            "@com_github_moby_profiles_seccomp//:seccomp",
            "@com_github_opencontainers_runtime_spec//specs-go",
            "@org_golang_x_sys//unix",
        ],
        "//conditions:default": [],
    }),
)

go_test(
    name = "seccomp_test",
    srcs = ["seccomp_test.go"],
    embed = [":seccomp"],
    target_compatible_with = ["@platforms//os:linux"],
    deps = select({
        "@io_bazel_rules_go//go/platform:android": [
            "@com_github_opencontainers_runtime_spec//specs-go",
            "@com_github_stretchr_testify//assert",
            "@com_github_stretchr_testify//require",
        ],
        "@io_bazel_rules_go//go/platform:linux": [
            "@com_github_opencontainers_runtime_spec//specs-go",
            "@com_github_stretchr_testify//assert",
            "@com_github_stretchr_testify//require",
        ],
        "//conditions:default": [],
    }),
)
