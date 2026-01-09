"""Pytest configuration and fixtures for LLDB MCP tests."""
import os
import sys
from pathlib import Path
from typing import Generator, Optional

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "requires_lldb: mark test as requiring LLDB Python bindings"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    """Return path to test samples directory."""
    return Path(__file__).parent / "samples"


@pytest.fixture(scope="session")
def hello_binary(samples_dir: Path) -> Path:
    """Return path to compiled hello test program."""
    binary = samples_dir / "hello"
    if not binary.exists():
        pytest.skip("hello binary not compiled. Run: gcc -g -o hello hello.c")
    return binary


@pytest.fixture(scope="session")
def threads_binary(samples_dir: Path) -> Path:
    """Return path to compiled threads test program."""
    binary = samples_dir / "threads"
    if not binary.exists():
        pytest.skip("threads binary not compiled. Run: gcc -g -pthread -o threads threads.c")
    return binary


@pytest.fixture
def lldb_available() -> bool:
    """Check if LLDB Python bindings are available."""
    try:
        import lldb
        return True
    except ImportError:
        return False


@pytest.fixture
def adapter(lldb_available):
    """Create and return an LldbAdapter instance."""
    if not lldb_available:
        pytest.skip("LLDB Python bindings not available")

    from lldb_mcp.lldb_adapter import LldbAdapter
    from lldb_mcp.config import ServerConfig

    config = ServerConfig(
        max_memory_read_size=10 * 1024 * 1024,  # 10MB for tests
        operation_timeout=60.0,
    )
    adapter = LldbAdapter(config=config)
    yield adapter
    adapter.close()


@pytest.fixture
def launched_adapter(adapter, hello_binary):
    """Create adapter with hello binary launched."""
    adapter.launch(str(hello_binary))
    yield adapter
    try:
        if adapter.process is not None:
            adapter.kill()
    except Exception:
        pass


@pytest.fixture
def stopped_at_main(launched_adapter):
    """Create adapter stopped at main function."""
    launched_adapter.breakpoint_set("main")
    launched_adapter.execution_continue()
    yield launched_adapter


@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    """Create temporary output directory for dump tests."""
    output_dir = tmp_path / "lldb_mcp_output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir
