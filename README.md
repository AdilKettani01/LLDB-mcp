# LLDB MCP

<<<<<<< HEAD
LLDB-backed MCP server for Linux ELF analysis and runtime debugging.

## Goals
- Provide MCP tools for breakpoints, stepping, register and memory inspection, and unpacking workflows.
- Keep LLDB interactions isolated behind a small adapter layer.

## Requirements
- Python 3.10+
- LLDB with Python bindings (module `lldb`)
- MCP Python library (to be finalized in TODO)

## Quickstart
```bash
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -e .
python -m lldb_mcp --log-level INFO
```

## Project layout
- `src/lldb_mcp/` - MCP server, tool handlers, and LLDB adapter
- `tests/` - test scaffolding
- `TODO.md` - roadmap and implementation checklist

## Planned tool surface
- `target.launch`, `target.attach`, `target.detach`, `target.kill`
- `breakpoint.set`, `breakpoint.clear`, `breakpoint.list`, `breakpoint.enable`, `breakpoint.disable`
- `execution.continue`, `execution.pause`, `execution.step`, `execution.finish`
- `registers.read`, `registers.write`
- `memory.read`, `memory.write`, `memory.search`, `memory.map`
- `threads.list`, `thread.select`, `stack.backtrace`
- `modules.list`, `symbols.resolve`
- `unpack.dump_memory`, `unpack.rebuild_elf`

## Status
Scaffold only. Tool handlers are stubs; see `TODO.md` for next steps.
=======
LLDB-backed MCP (Model Context Protocol) server for Linux ELF analysis and runtime debugging.

## Features

- **24 MCP Tools** for comprehensive debugging:
  - Target management: launch, attach, detach, kill
  - Breakpoints: set, clear, list, enable, disable
  - Execution control: continue, pause, step (into/over/out), finish
  - Registers: read, write
  - Memory: read, write, search, map
  - Threads: list, select
  - Stack: backtrace
  - Modules/Symbols: list, resolve
  - ELF Unpacking: dump_memory, rebuild_elf

- **Clean Architecture**: CLI → Server → Handlers → LldbAdapter → LLDB
- **Production Ready**: Error handling, configuration, security guardrails

## Requirements

- Python 3.10+
- LLDB with Python bindings (module `lldb`)
- MCP Python library (automatically installed)

### Installing LLDB Python Bindings

**Ubuntu/Debian:**
```bash
sudo apt install lldb python3-lldb
```

**Arch Linux:**
```bash
sudo pacman -S lldb
```

**macOS:**
```bash
# LLDB is included with Xcode command line tools
xcode-select --install
```

## Installation

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install the package
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

## Usage

### Run the MCP Server

```bash
# Via module
python -m lldb_mcp --log-level INFO

# Or via entry point
lldb-mcp --log-level DEBUG
```

### MCP Tool Examples

Once connected to the server via an MCP client:

```python
# Launch a target
target.launch(path="/path/to/binary", args=["arg1", "arg2"])

# Set a breakpoint
breakpoint.set(location="main")

# Continue execution
execution.continue()

# Read memory
memory.read(address="0x7fff12345678", length=64)

# Get backtrace
stack.backtrace(max_frames=10)

# Dump memory to file
unpack.dump_memory(start="0x400000", end="0x500000", output_path="/tmp/dump.bin")
```

## Project Structure

```
src/lldb_mcp/
├── __init__.py      # Package version
├── __main__.py      # Entry point
├── cli.py           # CLI argument parsing
├── server.py        # MCP server with 24 tool registrations
├── handlers.py      # Async tool handlers
├── lldb_adapter.py  # LLDB Python bindings adapter
├── config.py        # Server configuration
├── errors.py        # Error types
└── utils.py         # Utility functions

tests/
├── conftest.py      # Pytest fixtures
├── test_utils.py    # Unit tests for utilities
├── test_errors.py   # Unit tests for errors
├── test_config.py   # Unit tests for config
├── test_adapter.py  # Integration tests (requires LLDB)
└── samples/
    ├── hello.c      # Test binary source
    └── threads.c    # Multi-threaded test source
```

## Testing

```bash
# Run all tests (excluding LLDB integration tests)
pytest tests/ --ignore=tests/test_adapter.py -v

# Run with LLDB (requires LLDB Python bindings)
pytest tests/ -v

# Run linting
ruff check src/
```

## Configuration

Environment variables:
- `LLDB_MCP_LOG_LEVEL` - Logging level (default: INFO)
- `LLDB_MCP_OUTPUT_DIR` - Output directory for dumps
- `LLDB_MCP_MAX_MEMORY_READ` - Max memory read size in bytes
- `LLDB_MCP_TIMEOUT` - Operation timeout in seconds

## Security

The server includes security guardrails:
- Path allowlist/denylist for file writes
- Maximum memory operation sizes
- Operation timeouts
- Denied paths: `/etc`, `/root`, `/boot` by default

## License

MIT
>>>>>>> master
