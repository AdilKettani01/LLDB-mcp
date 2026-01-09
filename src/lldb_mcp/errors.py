"""Error types for LLDB MCP server."""
from __future__ import annotations

from typing import Any, Dict, Optional


class LldbMcpError(Exception):
    """Base exception for LLDB MCP errors."""

    code: int = 1000

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize error to dictionary."""
        return {"error": self.message, "code": self.code, "details": self.details}


class NoTargetError(LldbMcpError):
    """No target has been created."""

    code = 1001


class NoProcessError(LldbMcpError):
    """No process is currently being debugged."""

    code = 1002


class ProcessNotStoppedError(LldbMcpError):
    """Process is not in stopped state."""

    code = 1003


class InvalidAddressError(LldbMcpError):
    """Invalid memory address."""

    code = 1004


class BreakpointError(LldbMcpError):
    """Breakpoint operation failed."""

    code = 1005


class MemoryAccessError(LldbMcpError):
    """Memory access failed."""

    code = 1006


class PathSecurityError(LldbMcpError):
    """Path security violation."""

    code = 1007


class OperationTimeoutError(LldbMcpError):
    """Operation timed out."""

    code = 1008


class InvalidOperationError(LldbMcpError):
    """Invalid operation for current state."""

    code = 1009
