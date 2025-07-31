#!/usr/bin/env python3
"""
Test script to verify native extensions work correctly.
"""

import sys
import os

def test_native_import():
    """Test that native extensions can be imported."""
    try:
        import _bpftrace_native
        print("✓ Native extensions imported successfully")
        print(f"  Version: {_bpftrace_native.__version__}")
        return True
    except ImportError as e:
        print(f"✗ Failed to import native extensions: {e}")
        return False

def test_native_array_map():
    """Test native ArrayMap functionality."""
    try:
        import _bpftrace_native

        # Create array map
        arr = _bpftrace_native.NativeArrayMap(10, "test_array")
        print(f"✓ Created NativeArrayMap: {arr.name()}")

        # Test basic operations
        arr[0] = 42
        assert arr[0] == 42
        assert arr.get(0) == 42
        assert arr.get(1, -1) == -1  # Default value
        print("✓ NativeArrayMap basic operations work")

        # Test declaration
        decl = arr.to_bpftrace_declaration()
        expected = "@test_array[int64] = int64;"
        assert decl == expected
        print(f"✓ Declaration: {decl}")

        return True
    except Exception as e:
        print(f"✗ NativeArrayMap test failed: {e}")
        return False

def test_native_hash_map():
    """Test native HashMap functionality."""
    try:
        import _bpftrace_native

        # Create hash map
        hmap = _bpftrace_native.NativeHashMap("test_hash")
        print(f"✓ Created NativeHashMap: {hmap.name()}")

        # Test string keys
        hmap["key1"] = 100
        assert hmap["key1"] == 100

        # Test int keys
        hmap[42] = 200
        assert hmap[42] == 200

        print("✓ NativeHashMap basic operations work")

        return True
    except Exception as e:
        print(f"✗ NativeHashMap test failed: {e}")
        return False

def test_python_fallback():
    """Test that Python fallback works when native is not available."""
    # Temporarily hide the native module
    import sys
    native_module = sys.modules.get('_bpftrace_native')
    if native_module:
        del sys.modules['_bpftrace_native']

    try:
        # Force reimport of bpftrace module
        if 'bpftrace' in sys.modules:
            del sys.modules['bpftrace']

        import bpftrace

        # Should use pure Python implementation
        arr = bpftrace.ArrayMap(5, "fallback_test")
        arr[0] = 123
        assert arr[0] == 123
        print("✓ Python fallback works correctly")

        return True
    except Exception as e:
        print(f"✗ Python fallback test failed: {e}")
        return False
    finally:
        # Restore native module if it was there
        if native_module:
            sys.modules['_bpftrace_native'] = native_module

def test_transpiler_with_native():
    """Test that the transpiler works with native extensions."""
    try:
        import bpftrace

        # Create maps
        x = bpftrace.ArrayMap(10, "test_x")

        # Test constant
        TEST_VALUE = 42

        @bpftrace.kprobe("test_func")
        def test_probe():
            x[0] = TEST_VALUE
            if TEST_VALUE > 0:
                x[1] = 1

        # Generate script
        script = bpftrace._transpiler.generate_full_bpftrace_script()

        # Check that it contains expected elements
        assert "@test_x[int64] = int64;" in script
        assert "kprobe:test_func" in script
        assert "@test_x[0] = 42;" in script

        print("✓ Transpiler works with native extensions")
        return True
    except Exception as e:
        print(f"✗ Transpiler test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Testing bpftrace Python native extensions...")
    print("=" * 50)

    tests = [
        test_native_import,
        test_native_array_map,
        test_native_hash_map,
        test_python_fallback,
        test_transpiler_with_native,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        print(f"\nRunning {test.__name__}:")
        if test():
            passed += 1
        else:
            print("  Test failed!")

    print("\n" + "=" * 50)
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
