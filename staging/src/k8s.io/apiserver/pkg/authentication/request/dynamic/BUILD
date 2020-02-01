load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["dynamic.go"],
    importmap = "k8s.io/kubernetes/vendor/k8s.io/apiserver/pkg/authentication/request/dynamic",
    importpath = "k8s.io/apiserver/pkg/authentication/request/dynamic",
    visibility = ["//visibility:public"],
    deps = [
        "//staging/src/k8s.io/api/authentication/v1alpha1:go_default_library",
        "//staging/src/k8s.io/apimachinery/pkg/labels:go_default_library",
        "//staging/src/k8s.io/apimachinery/pkg/util/runtime:go_default_library",
        "//staging/src/k8s.io/apiserver/pkg/authentication/authenticator:go_default_library",
        "//staging/src/k8s.io/apiserver/pkg/authentication/request/bearertoken:go_default_library",
        "//staging/src/k8s.io/apiserver/pkg/authentication/request/union:go_default_library",
        "//staging/src/k8s.io/apiserver/pkg/authentication/request/websocket:go_default_library",
        "//staging/src/k8s.io/apiserver/pkg/authentication/request/x509:go_default_library",
        "//staging/src/k8s.io/apiserver/pkg/authentication/token/cache:go_default_library",
        "//staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc:go_default_library",
        "//staging/src/k8s.io/client-go/informers/authentication/v1alpha1:go_default_library",
        "//staging/src/k8s.io/client-go/listers/authentication/v1alpha1:go_default_library",
        "//staging/src/k8s.io/client-go/tools/cache:go_default_library",
        "//staging/src/k8s.io/client-go/util/cert:go_default_library",
        "//vendor/k8s.io/klog:go_default_library",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
