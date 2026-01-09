"""Tests for configuration module."""
import os
from pathlib import Path

import pytest

from lldb_mcp.config import ServerConfig
from lldb_mcp.errors import PathSecurityError


class TestServerConfig:
    """Tests for ServerConfig class."""

    def test_default_values(self):
        config = ServerConfig()
        assert config.log_level == "INFO"
        assert config.max_memory_read_size == 1024 * 1024
        assert config.max_memory_write_size == 1024 * 1024
        assert config.operation_timeout == 30.0
        assert config.output_directory is None
        assert config.allowed_paths == []
        assert config.async_mode is False

    def test_custom_values(self):
        config = ServerConfig(
            log_level="DEBUG",
            max_memory_read_size=2048,
            operation_timeout=60.0,
        )
        assert config.log_level == "DEBUG"
        assert config.max_memory_read_size == 2048
        assert config.operation_timeout == 60.0

    def test_denied_paths_default(self):
        config = ServerConfig()
        assert Path("/etc") in config.denied_paths
        assert Path("/root") in config.denied_paths
        assert Path("/boot") in config.denied_paths


class TestServerConfigFromEnv:
    """Tests for ServerConfig.from_env()."""

    def test_from_env_defaults(self, monkeypatch):
        # Clear any existing env vars
        for var in ["LLDB_MCP_LOG_LEVEL", "LLDB_MCP_OUTPUT_DIR",
                    "LLDB_MCP_MAX_MEMORY_READ", "LLDB_MCP_TIMEOUT"]:
            monkeypatch.delenv(var, raising=False)

        config = ServerConfig.from_env()
        assert config.log_level == "INFO"
        assert config.output_directory is None

    def test_from_env_custom(self, monkeypatch):
        monkeypatch.setenv("LLDB_MCP_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("LLDB_MCP_OUTPUT_DIR", "/tmp/output")
        monkeypatch.setenv("LLDB_MCP_MAX_MEMORY_READ", "2048")
        monkeypatch.setenv("LLDB_MCP_TIMEOUT", "120.0")

        config = ServerConfig.from_env()
        assert config.log_level == "DEBUG"
        assert config.output_directory == Path("/tmp/output")
        assert config.max_memory_read_size == 2048
        assert config.operation_timeout == 120.0


class TestPathValidation:
    """Tests for path validation."""

    def test_validate_allowed_path(self, tmp_path):
        config = ServerConfig(allowed_paths=[tmp_path])
        output = tmp_path / "test.bin"
        config.validate_output_path(output)  # Should not raise

    def test_validate_denied_path(self):
        config = ServerConfig()
        with pytest.raises(PathSecurityError):
            config.validate_output_path(Path("/etc/passwd"))

    def test_validate_path_traversal(self, tmp_path):
        config = ServerConfig(allowed_paths=[tmp_path])
        # Path with .. that resolves outside allowed
        bad_path = tmp_path / ".." / ".." / "etc" / "passwd"
        with pytest.raises(PathSecurityError):
            config.validate_output_path(bad_path)

    def test_validate_without_allowed_paths(self, tmp_path):
        # If no allowed_paths, any non-denied path should work
        config = ServerConfig(denied_paths=[])
        output = tmp_path / "test.bin"
        config.validate_output_path(output)  # Should not raise
