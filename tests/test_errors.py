"""Tests for error types."""
import pytest

from lldb_mcp.errors import (
    LldbMcpError,
    NoTargetError,
    NoProcessError,
    ProcessNotStoppedError,
    InvalidAddressError,
    BreakpointError,
    MemoryAccessError,
    PathSecurityError,
    OperationTimeoutError,
    InvalidOperationError,
)


class TestLldbMcpError:
    """Tests for base error class."""

    def test_basic_error(self):
        error = LldbMcpError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.code == 1000
        assert error.details == {}

    def test_error_with_details(self):
        error = LldbMcpError("Error", details={"key": "value"})
        assert error.details == {"key": "value"}

    def test_to_dict(self):
        error = LldbMcpError("Test", details={"foo": "bar"})
        d = error.to_dict()
        assert d["error"] == "Test"
        assert d["code"] == 1000
        assert d["details"] == {"foo": "bar"}


class TestSpecificErrors:
    """Tests for specific error types."""

    def test_no_target_error(self):
        error = NoTargetError("No target")
        assert error.code == 1001

    def test_no_process_error(self):
        error = NoProcessError("No process")
        assert error.code == 1002

    def test_process_not_stopped_error(self):
        error = ProcessNotStoppedError("Running")
        assert error.code == 1003

    def test_invalid_address_error(self):
        error = InvalidAddressError("Bad address")
        assert error.code == 1004

    def test_breakpoint_error(self):
        error = BreakpointError("BP failed")
        assert error.code == 1005

    def test_memory_access_error(self):
        error = MemoryAccessError("Read failed")
        assert error.code == 1006

    def test_path_security_error(self):
        error = PathSecurityError("Path denied")
        assert error.code == 1007

    def test_operation_timeout_error(self):
        error = OperationTimeoutError("Timeout")
        assert error.code == 1008

    def test_invalid_operation_error(self):
        error = InvalidOperationError("Invalid op")
        assert error.code == 1009


class TestErrorInheritance:
    """Tests for error inheritance."""

    def test_all_inherit_from_base(self):
        errors = [
            NoTargetError(""),
            NoProcessError(""),
            ProcessNotStoppedError(""),
            InvalidAddressError(""),
            BreakpointError(""),
            MemoryAccessError(""),
            PathSecurityError(""),
            OperationTimeoutError(""),
            InvalidOperationError(""),
        ]
        for error in errors:
            assert isinstance(error, LldbMcpError)
            assert isinstance(error, Exception)

    def test_can_catch_as_base(self):
        try:
            raise NoTargetError("Test")
        except LldbMcpError as e:
            assert e.code == 1001
