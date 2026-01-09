"""Tests for LLDB adapter functionality.

These tests require LLDB Python bindings and compiled test binaries.
Run with: pytest tests/test_adapter.py -v
"""
import pytest

from lldb_mcp.errors import (
    NoTargetError,
    NoProcessError,
    ProcessNotStoppedError,
    BreakpointError,
    InvalidOperationError,
)


pytestmark = pytest.mark.requires_lldb


class TestTargetManagement:
    """Tests for target launch/attach/detach/kill."""

    def test_launch_valid_binary(self, adapter, hello_binary):
        result = adapter.launch(str(hello_binary))
        assert "pid" in result
        assert result["pid"] > 0
        assert result["state"] in ["stopped", "running"]
        assert result["path"] == str(hello_binary)

    def test_launch_invalid_path(self, adapter):
        with pytest.raises(Exception) as exc_info:
            adapter.launch("/nonexistent/binary")
        assert "not found" in str(exc_info.value).lower()

    def test_kill_process(self, launched_adapter):
        result = launched_adapter.kill()
        assert result["killed"] is True
        assert "exit_code" in result

    def test_operations_without_target(self, adapter):
        with pytest.raises(NoTargetError):
            adapter.breakpoint_list()

    def test_operations_without_process(self, adapter, hello_binary):
        # Create target but don't launch
        adapter.target = adapter.debugger.CreateTarget(str(hello_binary))
        with pytest.raises(NoProcessError):
            adapter.execution_continue()


class TestBreakpoints:
    """Tests for breakpoint management."""

    def test_set_breakpoint_by_name(self, launched_adapter):
        result = launched_adapter.breakpoint_set("main")
        assert "id" in result
        assert result["id"] > 0
        assert result["locations"] > 0
        assert result["enabled"] is True

    def test_set_breakpoint_by_function(self, launched_adapter):
        result = launched_adapter.breakpoint_set("helper_function")
        assert result["id"] > 0

    def test_list_breakpoints(self, launched_adapter):
        launched_adapter.breakpoint_set("main")
        launched_adapter.breakpoint_set("compute")

        result = launched_adapter.breakpoint_list()
        assert result["count"] == 2
        assert len(result["breakpoints"]) == 2

    def test_enable_disable_breakpoint(self, launched_adapter):
        bp = launched_adapter.breakpoint_set("main")
        bp_id = str(bp["id"])

        # Disable
        result = launched_adapter.breakpoint_disable(bp_id)
        assert result["enabled"] is False

        # Verify in list
        bp_list = launched_adapter.breakpoint_list()
        bp_info = next(b for b in bp_list["breakpoints"] if b["id"] == bp["id"])
        assert bp_info["enabled"] is False

        # Enable
        result = launched_adapter.breakpoint_enable(bp_id)
        assert result["enabled"] is True

    def test_clear_breakpoint(self, launched_adapter):
        bp = launched_adapter.breakpoint_set("main")
        bp_id = str(bp["id"])

        result = launched_adapter.breakpoint_clear(bp_id)
        assert result["deleted"] is True

        # Verify removed from list
        bp_list = launched_adapter.breakpoint_list()
        assert all(b["id"] != bp["id"] for b in bp_list["breakpoints"])

    def test_invalid_breakpoint_id(self, launched_adapter):
        with pytest.raises(BreakpointError):
            launched_adapter.breakpoint_enable("9999")


class TestExecutionControl:
    """Tests for execution control (continue, step, etc)."""

    def test_continue_to_breakpoint(self, launched_adapter):
        launched_adapter.breakpoint_set("main")
        result = launched_adapter.execution_continue()
        assert result["state"] == "stopped"
        assert result["stop_reason"]["reason"] == "breakpoint"

    def test_step_over(self, stopped_at_main):
        result = stopped_at_main.execution_step("over")
        assert result["state"] == "stopped"
        assert "frame" in result
        assert result["frame"]["function"] is not None

    def test_step_into(self, stopped_at_main):
        # First continue past function declarations
        stopped_at_main.breakpoint_set("compute")
        stopped_at_main.execution_continue()

        # Now step into
        result = stopped_at_main.execution_step("into")
        assert result["state"] == "stopped"

    def test_step_invalid_kind(self, stopped_at_main):
        with pytest.raises(InvalidOperationError):
            stopped_at_main.execution_step("invalid_step_kind")

    def test_continue_without_stop(self, adapter, hello_binary):
        adapter.launch(str(hello_binary))
        # Process might be running - should handle gracefully
        # or be already stopped depending on launch behavior


class TestRegisters:
    """Tests for register read/write."""

    def test_read_registers(self, stopped_at_main):
        result = stopped_at_main.registers_read()
        assert "registers" in result
        assert len(result["registers"]) > 0
        # Should have General Purpose Registers
        has_gpr = any("general" in name.lower() for name in result["registers"].keys())
        assert has_gpr

    def test_read_registers_filtered(self, stopped_at_main):
        result = stopped_at_main.registers_read(group="general")
        assert "registers" in result
        # All groups should contain "general" in name
        for group_name in result["registers"].keys():
            assert "general" in group_name.lower()

    def test_write_register(self, stopped_at_main):
        # Read current value first
        regs = stopped_at_main.registers_read(group="general")

        # Try to write to a register (may fail if not writable)
        result = stopped_at_main.registers_write({"rax": "0x42"})
        assert "results" in result
        assert "rax" in result["results"]


class TestMemory:
    """Tests for memory read/write/search."""

    def test_read_memory(self, stopped_at_main):
        # Get the PC (program counter) and read from there
        bt = stopped_at_main.stack_backtrace()
        pc = bt["frames"][0]["pc"]

        result = stopped_at_main.memory_read(pc, 16)
        assert result["length"] == 16
        assert len(result["data"]) == 32  # hex encoding doubles length
        assert "ascii" in result

    def test_read_memory_invalid_length(self, stopped_at_main):
        from lldb_mcp.errors import MemoryAccessError
        with pytest.raises(MemoryAccessError):
            stopped_at_main.memory_read("0x0", 0)

    def test_memory_map(self, stopped_at_main):
        result = stopped_at_main.memory_map()
        assert "regions" in result
        assert result["count"] > 0

        # Should have at least one executable region
        has_exec = any(r["executable"] for r in result["regions"])
        assert has_exec

    def test_memory_search(self, stopped_at_main):
        # Search for the test string in memory
        mem_map = stopped_at_main.memory_map()

        # Find a readable region to search
        for region in mem_map["regions"]:
            if region["readable"] and region["size"] > 0 and region["size"] < 1024*1024:
                result = stopped_at_main.memory_search(
                    region["start"],
                    min(region["size"], 65536),
                    "LLDB_MCP",
                    encoding="ascii",
                    max_results=1
                )
                # May or may not find the string
                assert "matches" in result
                break


class TestThreadsAndStack:
    """Tests for thread and stack operations."""

    def test_threads_list(self, stopped_at_main):
        result = stopped_at_main.threads_list()
        assert "threads" in result
        assert result["count"] >= 1

        # At least one thread should be selected
        has_selected = any(t["selected"] for t in result["threads"])
        assert has_selected

    def test_stack_backtrace(self, stopped_at_main):
        result = stopped_at_main.stack_backtrace()
        assert "frames" in result
        assert result["count"] > 0

        # First frame should be main
        first_frame = result["frames"][0]
        assert first_frame["function"] == "main"
        assert first_frame["pc"] is not None

    def test_stack_backtrace_max_frames(self, stopped_at_main):
        result = stopped_at_main.stack_backtrace(max_frames=2)
        assert result["count"] <= 2

    def test_thread_select(self, stopped_at_main):
        threads = stopped_at_main.threads_list()
        thread_id = threads["threads"][0]["id"]

        result = stopped_at_main.thread_select(thread_id)
        assert result["selected"] == thread_id


class TestModulesAndSymbols:
    """Tests for module and symbol operations."""

    def test_modules_list(self, stopped_at_main):
        result = stopped_at_main.modules_list()
        assert "modules" in result
        assert result["count"] > 0

        # Should have the main executable
        hello_module = next(
            (m for m in result["modules"] if "hello" in m["name"]),
            None
        )
        assert hello_module is not None

    def test_symbols_resolve_by_name(self, stopped_at_main):
        result = stopped_at_main.symbols_resolve("main")
        assert "symbols" in result
        assert result["count"] > 0

        main_symbol = result["symbols"][0]
        assert "main" in main_symbol["name"]
        assert main_symbol["address"] is not None

    def test_symbols_resolve_by_address(self, stopped_at_main):
        # First get main's address
        main_result = stopped_at_main.symbols_resolve("main")
        main_addr = main_result["symbols"][0]["address"]

        # Now resolve by address
        result = stopped_at_main.symbols_resolve(main_addr)
        assert result["count"] > 0


class TestUnpacking:
    """Tests for memory dumping and ELF unpacking."""

    def test_dump_memory(self, stopped_at_main, tmp_output_dir):
        # Get a memory region to dump
        mem_map = stopped_at_main.memory_map()
        region = next(
            r for r in mem_map["regions"]
            if r["readable"] and r["size"] > 0 and r["size"] < 4096
        )

        output_path = tmp_output_dir / "dump.bin"
        result = stopped_at_main.unpack_dump_memory(
            region["start"],
            region["end"],
            str(output_path)
        )

        assert result["size"] > 0
        assert "hash_sha256" in result
        assert output_path.exists()

        # Metadata file should also exist
        meta_path = output_path.with_suffix(".bin.meta.json")
        assert meta_path.exists()
