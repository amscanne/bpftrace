#!/usr/bin/env python3
"""
Simple tests for the bpftrace Python transpiler.
"""

import os
import tempfile
import unittest

from bpftrace import ArrayMap, BpftraceTranspiler, HashMap


class TestBpftraceTranspiler(unittest.TestCase):
    """Test cases for the bpftrace transpiler."""

    def setUp(self):
        """Set up test fixtures."""
        self.transpiler = BpftraceTranspiler()

    def test_array_map_creation(self):
        """Test ArrayMap creation and basic operations."""
        arr = ArrayMap(10, "test_array")
        self.assertEqual(arr.size, 10)
        self.assertEqual(arr.name, "test_array")

        # Test setting and getting values
        arr[0] = 42
        self.assertEqual(arr[0], 42)
        self.assertEqual(arr.get(0), 42)
        self.assertEqual(arr.get(1, -1), -1)  # Default value

    def test_hash_map_creation(self):
        """Test HashMap creation and basic operations."""
        hmap = HashMap("test_hash")
        self.assertEqual(hmap.name, "test_hash")

        # Test setting and getting values
        hmap["key1"] = "value1"
        self.assertEqual(hmap["key1"], "value1")
        self.assertEqual(hmap.get("key1"), "value1")
        self.assertEqual(hmap.get("nonexistent", "default"), "default")

    def test_constant_resolution(self):
        """Test that constants are properly resolved."""
        # Create a test function with constants
        test_globals = {"foo": 42, "bar": "hello", "debug": True, "disabled": False}

        def test_func():
            x = foo
            msg = bar
            enabled = debug
            off = disabled

        # Transpile with captured globals
        code = self.transpiler.transpile_function(
            test_func, "kprobe", "test", test_globals
        )

        # Check that constants were resolved
        self.assertIn("$x = 42;", code)
        self.assertIn('$msg = "hello";', code)
        self.assertIn("$enabled = 1;", code)
        self.assertIn("$off = 0;", code)

    def test_control_flow_if_statement(self):
        """Test if statement transpilation."""
        test_globals = {"threshold": 10}

        def test_func():
            if threshold > 5:
                x = 1
            else:
                x = 0

        code = self.transpiler.transpile_function(
            test_func, "kprobe", "test", test_globals
        )

        self.assertIn("if ((10 > 5))", code)
        self.assertIn("$x = 1;", code)
        self.assertIn("} else {", code)
        self.assertIn("$x = 0;", code)

    def test_control_flow_for_loop(self):
        """Test for loop transpilation."""
        test_globals = {"max_iter": 5}

        def test_func():
            for i in range(max_iter):
                x = i

        code = self.transpiler.transpile_function(
            test_func, "kprobe", "test", test_globals
        )

        self.assertIn("$i = 0;", code)
        self.assertIn("while ($i < 5)", code)
        self.assertIn("$x = $i;", code)
        self.assertIn("$i++;", code)

    def test_control_flow_while_loop(self):
        """Test while loop transpilation."""
        test_globals = {"limit": 100}

        def test_func():
            while x < limit:
                x = x + 1

        code = self.transpiler.transpile_function(
            test_func, "kprobe", "test", test_globals
        )

        self.assertIn("while (($x < 100))", code)
        self.assertIn("$x = ($x + 1);", code)

    def test_map_operations(self):
        """Test map operations in transpiled code."""
        test_globals = {"my_map": ArrayMap(10, "my_map")}

        def test_func():
            my_map[0] = 42
            x = my_map[1]

        code = self.transpiler.transpile_function(
            test_func, "kprobe", "test", test_globals
        )

        self.assertIn("@my_map[0] = 42;", code)
        self.assertIn("$x = @my_map[1];", code)

    def test_probe_types(self):
        """Test different probe types."""

        def dummy_func():
            pass

        # Test kprobe
        code = self.transpiler.transpile_function(dummy_func, "kprobe", "sys_open", {})
        self.assertIn("kprobe:sys_open", code)

        # Test uprobe
        code = self.transpiler.transpile_function(
            dummy_func, "uprobe", "/bin/bash:main", {}
        )
        self.assertIn("uprobe:/bin/bash:main", code)

        # Test tracepoint
        code = self.transpiler.transpile_function(
            dummy_func, "tracepoint", "syscalls:sys_enter_open", {}
        )
        self.assertIn("tracepoint:syscalls:sys_enter_open", code)

    def test_expression_conversion(self):
        """Test expression conversion."""
        test_globals = {"a": 10, "b": 20}

        def test_func():
            result = a + b * 2
            comparison = a < b

        code = self.transpiler.transpile_function(
            test_func, "kprobe", "test", test_globals
        )

        self.assertIn("$result = (10 + (20 * 2));", code)
        self.assertIn("$comparison = (10 < 20);", code)

    def test_print_conversion(self):
        """Test print statement conversion."""
        test_globals = {"message": "Hello World"}

        def test_func():
            print(message)

        code = self.transpiler.transpile_function(
            test_func, "kprobe", "test", test_globals
        )

        self.assertIn('printf("%s\\n", "Hello World");', code)

    def test_full_script_generation(self):
        """Test full bpftrace script generation."""
        # Register some maps
        arr = ArrayMap(5, "test_array")
        hmap = HashMap("test_hash")
        self.transpiler.register_map(arr)
        self.transpiler.register_map(hmap)

        # Add a probe function
        def test_probe():
            test_array[0] = 1

        from bpftrace import ProbeFunction

        probe_func = ProbeFunction(
            func=test_probe,
            probe_type="kprobe",
            probe_target="test",
            bpftrace_code=self.transpiler.transpile_function(
                test_probe, "kprobe", "test", {}
            ),
            captured_globals={},
        )
        self.transpiler.probe_functions.append(probe_func)

        # Generate full script
        script = self.transpiler.generate_full_bpftrace_script()

        self.assertIn("#!/usr/bin/env bpftrace", script)
        self.assertIn("@test_array[int64] = int64;", script)
        self.assertIn("@test_hash[int64] = int64;", script)
        self.assertIn("kprobe:test", script)
        self.assertIn("END", script)


class TestIntegration(unittest.TestCase):
    """Integration tests using the decorator API."""

    def test_decorator_api(self):
        """Test the decorator API works correctly."""
        import bpftrace

        # Reset the global transpiler for clean test
        bpftrace._transpiler = BpftraceTranspiler()

        # Create test constants and maps
        TEST_VALUE = 42
        test_map = bpftrace.ArrayMap(10, "test_map")

        @bpftrace.kprobe("test_func")
        def my_probe():
            test_map[0] = TEST_VALUE
            if TEST_VALUE > 0:
                test_map[1] = 1

        # Check that the probe was registered
        self.assertEqual(len(bpftrace._transpiler.probe_functions), 1)
        probe_func = bpftrace._transpiler.probe_functions[0]
        self.assertEqual(probe_func.probe_type, "kprobe")
        self.assertEqual(probe_func.probe_target, "test_func")

        # Check that constants were captured
        self.assertIn("TEST_VALUE", probe_func.captured_globals)
        self.assertEqual(probe_func.captured_globals["TEST_VALUE"], 42)

        # Check generated code
        code = probe_func.bpftrace_code
        self.assertIn("@test_map[0] = 42;", code)
        self.assertIn("if ((42 > 0))", code)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
