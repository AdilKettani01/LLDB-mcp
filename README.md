# LLDB MCP

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
