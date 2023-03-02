workspace(name = "cilium")

register_toolchains("//bazel/toolchains:all")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_PROJECT = "envoyproxy"

ENVOY_REPO = "envoy"

# https://github.com/envoyproxy/envoy/tree/v1.24.3
# NOTE: Update version number to file 'ENVOY_VERSION' to keep test and build docker images
# for different versions.
ENVOY_SHA = "de8a30557c4a3b8bafba32b010aada485a3b9dd5"

ENVOY_SHA256 = "a3d93da0984b8482c5e26e9702160ee8bd524c31525ae9e3ed807810ca41fd11"

# // clang-format off: unexpected @bazel_tools reference, please indirect via a definition in //bazel
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
# // clang-format on

local_repository(
    name = "envoy_build_config",
    path = "envoy_build_config",
)

http_archive(
    name = "envoy",
    patch_args = ["apply"],
    patch_tool = "git",
    patches = [
        "@//patches:0001-network-Add-callback-for-upstream-authorization.patch",
        "@//patches:0002-upstream-Add-callback-for-upstream-authorization.patch",
        "@//patches:0003-connection-Make-isHalfCloseEnabled-const.patch",
        "@//patches:0004-tcp_proxy-Add-option-to-read-before-connect.patch",
        "@//patches:0005-router-Do-not-crash-if-SNI-was-already-set-with-auto.patch",
        "@//patches:0006-tcmalloc-Update-for-arm64-support.patch",
    ],
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    # // clang-format off: Envoy's format check: Only repository_locations.bzl may contains URL references
    url = "https://github.com/" + ENVOY_PROJECT + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
    # // clang-format on
)

#
# Bazel does not do transitive dependencies, so we must basically
# include all of Envoy's WORKSPACE file below, with the following
# changes:
# - Skip the 'workspace(name = "envoy")' line as we already defined
#   the workspace above.
# - loads of "//..." need to be renamed as "@envoy//..."
#

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()
