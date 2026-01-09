"""Configuration for LLDB MCP server."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ServerConfig:
    """Configuration settings for the LLDB MCP server."""

    log_level: str = "INFO"
    max_memory_read_size: int = 1024 * 1024  # 1MB default
    max_memory_write_size: int = 1024 * 1024  # 1MB default
    operation_timeout: float = 30.0  # seconds
    output_directory: Optional[Path] = None
    allowed_paths: List[Path] = field(default_factory=list)
    denied_paths: List[Path] = field(
        default_factory=lambda: [Path("/etc"), Path("/root"), Path("/boot")]
    )
    async_mode: bool = False

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables.

        Environment variables:
        - LLDB_MCP_LOG_LEVEL: Logging level (default: INFO)
        - LLDB_MCP_OUTPUT_DIR: Output directory for dumps
        - LLDB_MCP_MAX_MEMORY_READ: Max memory read size in bytes
        - LLDB_MCP_TIMEOUT: Operation timeout in seconds
        """
        output_dir = os.getenv("LLDB_MCP_OUTPUT_DIR")
        max_read = os.getenv("LLDB_MCP_MAX_MEMORY_READ")
        timeout = os.getenv("LLDB_MCP_TIMEOUT")

        return cls(
            log_level=os.getenv("LLDB_MCP_LOG_LEVEL", "INFO"),
            output_directory=Path(output_dir) if output_dir else None,
            max_memory_read_size=int(max_read) if max_read else 1024 * 1024,
            operation_timeout=float(timeout) if timeout else 30.0,
        )

    def validate_output_path(self, path: Path) -> None:
        """Validate that an output path is allowed.

        Args:
            path: Path to validate

        Raises:
            PathSecurityError: If path is not allowed
        """
        from .errors import PathSecurityError

        path = path.resolve()

        # Check against denied paths
        for denied in self.denied_paths:
            try:
                path.relative_to(denied.resolve())
                raise PathSecurityError(
                    f"Path {path} is in denied directory {denied}"
                )
            except ValueError:
                # Not relative to denied path, continue
                pass

        # Check against allowed paths if configured
        if self.allowed_paths:
            allowed = False
            for allowed_path in self.allowed_paths:
                try:
                    path.relative_to(allowed_path.resolve())
                    allowed = True
                    break
                except ValueError:
                    pass
            if not allowed:
                raise PathSecurityError(
                    f"Path {path} is not in allowed directories"
                )

        # Prevent path traversal via ".."
        if ".." in str(path):
            raise PathSecurityError("Path traversal not allowed")


# Default configuration instance
default_config = ServerConfig()
