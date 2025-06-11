"""
Build definitions that work with both Bazel and Buck2.

This file provides wrapper macros that abstract the differences between
Bazel and Buck2 build systems, allowing the same build definitions to
work with both systems.
"""

def _is_buck():
    """Detect if we're running under Buck2."""
    # Buck2 has native.read_config, Bazel doesn't
    return hasattr(native, "read_config")

def _get_cc_library():
    """Get the appropriate cc_library rule for the current build system."""
    if _is_buck():
        return native.cxx_library
    else:
        # Bazel
        return native.cc_library

def _get_cc_binary():
    """Get the appropriate cc_binary rule for the current build system."""
    if _is_buck():
        return native.cxx_binary
    else:
        # Bazel
        return native.cc_binary

def _normalize_deps(deps):
    """Normalize dependency references for the current build system."""
    if not deps:
        return []

    if _is_buck():
        # Buck2 uses different syntax for some dependencies
        normalized = []
        for dep in deps:
            if dep.startswith("@"):
                # External dependencies - Buck2 handles these differently
                # For now, keep as-is, but this might need project-specific mapping
                normalized.append(dep)
            else:
                normalized.append(dep)
        return normalized
    else:
        # Bazel - return as-is
        return deps

def _normalize_srcs(srcs):
    """Normalize source file references for the current build system."""
    if not srcs:
        return []

    if _is_buck():
        # Buck2 might need different handling for generated files
        normalized = []
        for src in srcs:
            if src.startswith("//"):
                # Cross-package references
                normalized.append(src)
            elif src.startswith(":"):
                # Same-package references
                normalized.append(src)
            else:
                # Regular files
                normalized.append(src)
        return normalized
    else:
        # Bazel - return as-is
        return srcs

def cc_library(
        name,
        srcs = None,
        hdrs = None,
        deps = None,
        includes = None,
        copts = None,
        linkopts = None,
        visibility = None,
        **kwargs):
    """Cross-platform cc_library that works with both Bazel and Buck2."""

    rule = _get_cc_library()

    # Normalize arguments
    normalized_deps = _normalize_deps(deps)
    normalized_srcs = _normalize_srcs(srcs)

    if _is_buck():
        # Buck2-specific argument mapping
        args = {
            "name": name,
        }

        if normalized_srcs:
            args["srcs"] = normalized_srcs
        if hdrs:
            args["headers"] = hdrs  # Buck2 uses 'headers' instead of 'hdrs'
        if normalized_deps:
            args["deps"] = normalized_deps
        if includes:
            # Buck2 uses exported_headers for include directories
            args["header_namespace"] = ""
            # Include paths need to be handled differently in Buck2
        if copts:
            args["compiler_flags"] = copts  # Buck2 uses 'compiler_flags'
        if linkopts:
            args["linker_flags"] = linkopts  # Buck2 uses 'linker_flags'
        if visibility:
            args["visibility"] = visibility

        # Add any additional kwargs
        args.update(kwargs)

    else:
        # Bazel arguments
        args = {
            "name": name,
        }

        if normalized_srcs:
            args["srcs"] = normalized_srcs
        if hdrs:
            args["hdrs"] = hdrs
        if normalized_deps:
            args["deps"] = normalized_deps
        if includes:
            args["includes"] = includes
        if copts:
            args["copts"] = copts
        if linkopts:
            args["linkopts"] = linkopts
        if visibility:
            args["visibility"] = visibility

        # Add any additional kwargs
        args.update(kwargs)

    rule(**args)

def cc_binary(
        name,
        srcs = None,
        deps = None,
        includes = None,
        copts = None,
        linkopts = None,
        visibility = None,
        **kwargs):
    """Cross-platform cc_binary that works with both Bazel and Buck2."""

    rule = _get_cc_binary()

    # Normalize arguments
    normalized_deps = _normalize_deps(deps)
    normalized_srcs = _normalize_srcs(srcs)

    if _is_buck():
        # Buck2-specific argument mapping
        args = {
            "name": name,
        }

        if normalized_srcs:
            args["srcs"] = normalized_srcs
        if normalized_deps:
            args["deps"] = normalized_deps
        if copts:
            args["compiler_flags"] = copts
        if linkopts:
            args["linker_flags"] = linkopts
        if visibility:
            args["visibility"] = visibility

        # Add any additional kwargs
        args.update(kwargs)

    else:
        # Bazel arguments
        args = {
            "name": name,
        }

        if normalized_srcs:
            args["srcs"] = normalized_srcs
        if normalized_deps:
            args["deps"] = normalized_deps
        if includes:
            args["includes"] = includes
        if copts:
            args["copts"] = copts
        if linkopts:
            args["linkopts"] = linkopts
        if visibility:
            args["visibility"] = visibility

        # Add any additional kwargs
        args.update(kwargs)

    rule(**args)

def filegroup(name, srcs = None, visibility = None, **kwargs):
    """Cross-platform filegroup that works with both Bazel and Buck2."""

    if _is_buck():
        # Buck2 uses filegroup as well, but might have different semantics
        native.filegroup(
            name = name,
            srcs = srcs or [],
            visibility = visibility,
            **kwargs
        )
    else:
        # Bazel
        native.filegroup(
            name = name,
            srcs = srcs or [],
            visibility = visibility,
            **kwargs
        )

def genrule(
        name,
        srcs = None,
        outs = None,
        cmd = None,
        tools = None,
        visibility = None,
        **kwargs):
    """Cross-platform genrule that works with both Bazel and Buck2."""

    if _is_buck():
        # Buck2 uses genrule but with different argument names
        native.genrule(
            name = name,
            srcs = srcs or [],
            out = outs[0] if outs and len(outs) == 1 else None,  # Buck2 uses 'out' for single output
            outs = outs if outs and len(outs) > 1 else None,     # Buck2 uses 'outs' for multiple outputs
            cmd = cmd,
            visibility = visibility,
            **kwargs
        )
    else:
        # Bazel
        native.genrule(
            name = name,
            srcs = srcs or [],
            outs = outs or [],
            cmd = cmd,
            tools = tools or [],
            visibility = visibility,
            **kwargs
        )

def sh_binary(name, srcs = None, visibility = None, **kwargs):
    """Cross-platform sh_binary that works with both Bazel and Buck2."""

    if _is_buck():
        # Buck2 uses sh_binary
        native.sh_binary(
            name = name,
            main = srcs[0] if srcs else None,  # Buck2 uses 'main' instead of 'srcs'
            visibility = visibility,
            **kwargs
        )
    else:
        # Bazel
        native.sh_binary(
            name = name,
            srcs = srcs or [],
            visibility = visibility,
            **kwargs
        )

# Platform detection utilities
def get_build_system():
    """Return the name of the current build system."""
    return "buck2" if _is_buck() else "bazel"

def select_for_build_system(bazel_value, buck2_value):
    """Select a value based on the current build system."""
    return buck2_value if _is_buck() else bazel_value
