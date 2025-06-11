load("//:build_defs.bzl", "cc_binary", "filegroup", "genrule")

# Version configuration with build stamping
genrule(
    name = "version_h",
    srcs = ["src/version.h.in"],
    out = "version.h",
    cmd = """
        sed -e 's/@bpftrace_VERSION_MAJOR@/0/g' \
            -e 's/@bpftrace_VERSION_MINOR@/23/g' \
            -e 's/@bpftrace_VERSION_PATCH@/0/g' \
            -e 's/@BPFTRACE_GIT_COMMIT_ID@/unknown/g' \
            -e 's/@BPFTRACE_GIT_COMMIT_DATE@/unknown/g' \
            $< > $@
    """,
)

# Main executable
cc_binary(
    name = "bpftrace",
    srcs = [
        "src/benchmark.cpp",
        "src/main.cpp",
    ],
    deps = ["//src:libbpftrace"],
    visibility = ["PUBLIC"],
)

# Install tools (*.bt files)
filegroup(
    name = "bt_tools",
    srcs = glob(["tools/*.bt"]),
)

# Test data and other files
filegroup(
    name = "test_data",
    srcs = glob([
        "tests/**/*",
        "man/**/*",
        "scripts/**/*",
    ]),
)
