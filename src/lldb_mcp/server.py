"""MCP Server for LLDB debugging."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .handlers import ToolHandlers

try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    FastMCP = None


def build_server() -> "FastMCP":
    """Build and configure the MCP server with all tools."""
    if FastMCP is None:
        raise RuntimeError(
            "mcp package not available. Install the MCP Python library and retry."
        )

    server = FastMCP(
        "lldb-mcp",
        instructions="""LLDB MCP Server - A debugger interface for Linux ELF analysis.

WORKFLOW:
1. Launch a target binary with target.launch OR attach to a running process with target.attach
2. Set breakpoints using breakpoint.set (by function name like "main", address like "0x401000", or file:line)
3. Continue execution with execution.continue - process will stop at breakpoints
4. Inspect state: registers.read, memory.read, stack.backtrace, threads.list
5. Step through code: execution.step (into/over/out) or execution.finish
6. When done: target.kill or target.detach

IMPORTANT:
- Most operations require a stopped process (after hitting breakpoint or stepping)
- Memory addresses can be hex (0x...) or decimal
- Use memory.map to see all memory regions before reading/writing
- Use modules.list and symbols.resolve to find function addresses
"""
    )
    handlers = ToolHandlers()

    # -------------------------------------------------------------------------
    # Target management tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="target.launch",
        description="""Launch a new process for debugging.

This is typically the first step - launch a binary to debug it.
The process will start and immediately stop (before main).

Parameters:
- path: Absolute path to the executable (e.g., "/usr/bin/ls", "./my_program")
- args: Command line arguments as a list (e.g., ["-la", "/tmp"])
- cwd: Working directory for the process
- env: Environment variables as key-value pairs

Returns: {pid, state, path}
- pid: Process ID of launched process
- state: "stopped" (ready for debugging) or "running"
- path: Resolved absolute path to the executable

Example: target.launch(path="./hello", args=["arg1"], cwd="/tmp")
After launch, set breakpoints and use execution.continue to run."""
    )
    async def tool_target_launch(
        path: str,
        args: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        return await handlers.target_launch(path, args=args, cwd=cwd, env=env)

    @server.tool(
        name="target.attach",
        description="""Attach to an already running process by PID.

Use this to debug a process that's already running.
The process will be stopped upon successful attach.

Parameters:
- pid: Process ID (integer) to attach to

Returns: {pid, state, attached}

Note: Requires appropriate permissions (may need sudo or ptrace capabilities).
After attaching, the process is stopped and ready for inspection."""
    )
    async def tool_target_attach(pid: int) -> Dict[str, Any]:
        return await handlers.target_attach(pid)

    @server.tool(
        name="target.detach",
        description="""Detach from the current process, leaving it running.

Use this when you want to stop debugging but let the process continue.
The process will resume execution after detach.

Returns: {detached: true}"""
    )
    async def tool_target_detach() -> Dict[str, Any]:
        return await handlers.target_detach()

    @server.tool(
        name="target.kill",
        description="""Kill/terminate the current process.

Use this to end the debugging session and terminate the process.

Returns: {killed: true, exit_code: <exit status>}"""
    )
    async def tool_target_kill() -> Dict[str, Any]:
        return await handlers.target_kill()

    # -------------------------------------------------------------------------
    # Breakpoint tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="breakpoint.set",
        description="""Set a breakpoint to stop execution at a specific location.

Location formats supported:
- Function name: "main", "printf", "MyClass::method"
- Address (hex): "0x401000" or "401000" (8+ hex chars assumed hex)
- File:line: "main.c:42", "src/foo.cpp:100"

Parameters:
- location: Where to set breakpoint (function name, address, or file:line)
- condition: Optional expression that must be true to stop (e.g., "x > 10")
- hardware: Request hardware breakpoint (limited quantity, faster)

Returns: {id, locations, enabled, condition, location_details}
- id: Breakpoint ID (use this to enable/disable/clear)
- locations: Number of addresses where breakpoint was set
- location_details: List of {address, resolved} for each location

Example: breakpoint.set(location="main")
         breakpoint.set(location="0x401000")
         breakpoint.set(location="loop", condition="i == 100")"""
    )
    async def tool_breakpoint_set(
        location: str,
        condition: Optional[str] = None,
        hardware: bool = False,
    ) -> Dict[str, Any]:
        return await handlers.breakpoint_set(
            location, condition=condition, hardware=hardware
        )

    @server.tool(
        name="breakpoint.clear",
        description="""Delete/remove a breakpoint by its ID.

Parameters:
- breakpoint_id: The ID returned when breakpoint was created (as string)

Returns: {deleted: true/false, id}"""
    )
    async def tool_breakpoint_clear(breakpoint_id: str) -> Dict[str, Any]:
        return await handlers.breakpoint_clear(breakpoint_id)

    @server.tool(
        name="breakpoint.list",
        description="""List all current breakpoints and their status.

Returns: {breakpoints: [...], count}
Each breakpoint has: {id, enabled, hit_count, condition, locations, num_locations}

Use this to see what breakpoints are active before continuing execution."""
    )
    async def tool_breakpoint_list() -> Dict[str, Any]:
        return await handlers.breakpoint_list()

    @server.tool(
        name="breakpoint.enable",
        description="""Enable a previously disabled breakpoint.

Parameters:
- breakpoint_id: The breakpoint ID (as string)

Returns: {id, enabled: true}"""
    )
    async def tool_breakpoint_enable(breakpoint_id: str) -> Dict[str, Any]:
        return await handlers.breakpoint_enable(breakpoint_id)

    @server.tool(
        name="breakpoint.disable",
        description="""Disable a breakpoint without deleting it.

Disabled breakpoints won't stop execution but can be re-enabled later.

Parameters:
- breakpoint_id: The breakpoint ID (as string)

Returns: {id, enabled: false}"""
    )
    async def tool_breakpoint_disable(breakpoint_id: str) -> Dict[str, Any]:
        return await handlers.breakpoint_disable(breakpoint_id)

    # -------------------------------------------------------------------------
    # Execution control tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="execution.continue",
        description="""Continue/resume execution until next breakpoint or exit.

The process must be stopped (at a breakpoint or after stepping).
Execution continues until:
- A breakpoint is hit
- A signal/exception occurs
- The process exits

Returns: {state, thread_id, stop_reason, frame}
- state: "stopped", "running", "exited", etc.
- stop_reason: {reason: "breakpoint"/"signal"/"none", ...}
- frame: Current stack frame if stopped

After continue returns with state="stopped", you can inspect registers, memory, etc."""
    )
    async def tool_execution_continue() -> Dict[str, Any]:
        return await handlers.execution_continue()

    @server.tool(
        name="execution.pause",
        description="""Pause/interrupt a running process.

Use this to stop a process that's currently running (e.g., in a loop).

Returns: {state}"""
    )
    async def tool_execution_pause() -> Dict[str, Any]:
        return await handlers.execution_pause()

    @server.tool(
        name="execution.step",
        description="""Execute a single step in the program.

Step types:
- "into": Step into function calls (descend into called functions)
- "over": Step over function calls (execute call as single step)
- "out": Step out of current function (run until return)
- "instruction": Step single CPU instruction

Parameters:
- kind: One of "into", "over", "out", "instruction"

Returns: {state, thread_id, frame, stop_reason}
- frame: New location after step {pc, function, file, line, ...}

Example workflow:
1. breakpoint.set(location="main")
2. execution.continue()  # stops at main
3. execution.step(kind="over")  # step one line
4. execution.step(kind="into")  # step into function call"""
    )
    async def tool_execution_step(kind: str) -> Dict[str, Any]:
        return await handlers.execution_step(kind)

    @server.tool(
        name="execution.finish",
        description="""Run until current function returns (step out).

Equivalent to execution.step(kind="out").
Continues until the current function returns to its caller.

Returns: {state, thread_id, frame, stop_reason}"""
    )
    async def tool_execution_finish() -> Dict[str, Any]:
        return await handlers.execution_finish()

    # -------------------------------------------------------------------------
    # Register tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="registers.read",
        description="""Read CPU register values.

Process must be stopped. Returns registers organized by group.

Parameters:
- group: Optional filter - "general", "floating", etc. (case-insensitive substring match)

Returns: {registers: {group_name: {reg_name: value, ...}, ...}, thread_id}

Common x86_64 registers:
- General: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15
- rip: Instruction pointer (current execution address)
- rflags: Status flags

Example: registers.read(group="general")"""
    )
    async def tool_registers_read(group: Optional[str] = None) -> Dict[str, Any]:
        return await handlers.registers_read(group=group)

    @server.tool(
        name="registers.write",
        description="""Write/modify CPU register values.

Process must be stopped. Use with caution - can crash the process.

Parameters:
- registers: Dict of register_name -> value (as hex string or decimal)

Returns: {results: {reg_name: {success, new_value, error}, ...}, thread_id}

Example: registers.write(registers={"rax": "0x42", "rbx": "100"})"""
    )
    async def tool_registers_write(registers: Dict[str, str]) -> Dict[str, Any]:
        return await handlers.registers_write(registers)

    # -------------------------------------------------------------------------
    # Memory tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="memory.read",
        description="""Read bytes from process memory.

Parameters:
- address: Start address (hex like "0x7fff1234" or decimal)
- length: Number of bytes to read (max 1MB by default)

Returns: {address, length, data, ascii}
- data: Hex string of bytes (e.g., "48656c6c6f" for "Hello")
- ascii: ASCII representation with '.' for non-printable bytes

Use memory.map first to find valid readable regions.
Example: memory.read(address="0x7fff12340000", length=64)"""
    )
    async def tool_memory_read(address: str, length: int) -> Dict[str, Any]:
        return await handlers.memory_read(address, length)

    @server.tool(
        name="memory.write",
        description="""Write bytes to process memory.

Use with extreme caution - can crash or corrupt the process.

Parameters:
- address: Start address (hex or decimal)
- data: Data to write
- encoding: How 'data' is encoded:
  - "hex" (default): data is hex string like "48656c6c6f"
  - "ascii": data is ASCII string like "Hello"
  - "utf8": data is UTF-8 string

Returns: {address, bytes_written, success}

Example: memory.write(address="0x7fff1234", data="90909090", encoding="hex")  # NOP sled
         memory.write(address="0x7fff1234", data="Hello", encoding="ascii")"""
    )
    async def tool_memory_write(
        address: str, data: str, encoding: Optional[str] = None
    ) -> Dict[str, Any]:
        return await handlers.memory_write(address, data, encoding=encoding)

    @server.tool(
        name="memory.search",
        description="""Search memory for a byte pattern.

Parameters:
- address: Start address to search from
- length: Number of bytes to search through
- pattern: Pattern to find
- encoding: Pattern encoding - "hex" (default), "ascii", or "utf8"
- max_results: Maximum matches to return (default 10)

Returns: {pattern, encoding, matches: [addresses...], count, truncated}

Example: memory.search(address="0x400000", length=0x10000, pattern="ELF", encoding="ascii")
         memory.search(address="0x400000", length=0x10000, pattern="7f454c46", encoding="hex")"""
    )
    async def tool_memory_search(
        address: str,
        length: int,
        pattern: str,
        encoding: Optional[str] = None,
        max_results: int = 10,
    ) -> Dict[str, Any]:
        return await handlers.memory_search(
            address,
            length,
            pattern,
            encoding=encoding,
            max_results=max_results,
        )

    @server.tool(
        name="memory.map",
        description="""Get the memory map showing all memory regions.

Returns all mapped memory regions with their permissions.
Use this to find valid addresses before reading/writing memory.

Returns: {regions: [...], count}
Each region: {start, end, size, permissions, readable, writable, executable, name, mapped}
- permissions: String like "rwx", "r-x", "rw-"
- name: Region name if available (e.g., "[heap]", "[stack]", library path)

Example output regions:
- 0x400000-0x401000 r-x (executable code)
- 0x7fff...-0x7fff... rw- [stack]"""
    )
    async def tool_memory_map() -> Dict[str, Any]:
        return await handlers.memory_map()

    # -------------------------------------------------------------------------
    # Thread and stack tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="threads.list",
        description="""List all threads in the process.

Returns: {threads: [...], count}
Each thread: {id, index, name, queue, selected, num_frames, stop_reason, frame}
- id: Thread ID (use with thread.select)
- selected: true if this is the currently selected thread
- frame: Current stack frame for this thread

Multi-threaded programs will have multiple threads. Use thread.select to switch."""
    )
    async def tool_threads_list() -> Dict[str, Any]:
        return await handlers.threads_list()

    @server.tool(
        name="thread.select",
        description="""Select/switch to a different thread.

After selecting, operations like registers.read and stack.backtrace
will operate on the selected thread.

Parameters:
- thread_id: Thread ID from threads.list

Returns: {selected, name, num_frames, frame}"""
    )
    async def tool_thread_select(thread_id: int) -> Dict[str, Any]:
        return await handlers.thread_select(thread_id)

    @server.tool(
        name="stack.backtrace",
        description="""Get the call stack (backtrace) showing function call chain.

Shows the sequence of function calls that led to the current location.
Frame 0 is the current function, frame 1 is its caller, etc.

Parameters:
- thread_id: Optional thread ID (uses selected thread if not specified)
- max_frames: Maximum frames to return (default 64)

Returns: {thread_id, frames: [...], count, total_frames, truncated}
Each frame: {index, pc, sp, fp, function, file, line, column, module}
- pc: Program counter (instruction address)
- function: Function name
- file/line: Source location if debug info available

Example output:
  #0 helper_func at main.c:10
  #1 main at main.c:25
  #2 __libc_start_main"""
    )
    async def tool_stack_backtrace(
        thread_id: Optional[int] = None, max_frames: int = 64
    ) -> Dict[str, Any]:
        return await handlers.stack_backtrace(
            thread_id=thread_id, max_frames=max_frames
        )

    # -------------------------------------------------------------------------
    # Module and symbol tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="modules.list",
        description="""List all loaded modules (executable and shared libraries).

Returns: {modules: [...], count}
Each module: {name, path, uuid, num_sections, sections: [...], num_symbols}
Each section: {name, address, size, file_offset, type}

Useful for:
- Finding the base address of libraries
- Understanding memory layout
- Finding code/data sections"""
    )
    async def tool_modules_list() -> Dict[str, Any]:
        return await handlers.modules_list()

    @server.tool(
        name="symbols.resolve",
        description="""Resolve a symbol name to address or address to symbol.

Parameters:
- query: Symbol name (e.g., "main", "printf") OR address (e.g., "0x401000")

Returns: {query, symbols: [...], count}
Each symbol: {name, mangled_name, address, size/module, type}

Use cases:
- Find address of a function: symbols.resolve(query="main")
- Find what function an address belongs to: symbols.resolve(query="0x401234")

Useful for setting breakpoints by address or understanding code layout."""
    )
    async def tool_symbols_resolve(query: str) -> Dict[str, Any]:
        return await handlers.symbols_resolve(query)

    # -------------------------------------------------------------------------
    # ELF unpacking tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="unpack.dump_memory",
        description="""Dump a memory range to a file.

Saves raw bytes from memory to disk. Useful for:
- Extracting unpacked code from memory
- Saving memory regions for offline analysis
- Forensic capture of process memory

Parameters:
- start: Start address (hex or decimal)
- end: End address (must be > start)
- output_path: File path to save to (will be created)

Returns: {start, end, size, hash_sha256, hash_md5, output, errors}
Also creates a .meta.json file with metadata.

Example: unpack.dump_memory(start="0x400000", end="0x500000", output_path="/tmp/code.bin")"""
    )
    async def tool_unpack_dump_memory(
        start: str, end: str, output_path: str
    ) -> Dict[str, Any]:
        return await handlers.unpack_dump_memory(start, end, output_path)

    @server.tool(
        name="unpack.rebuild_elf",
        description="""Rebuild an ELF file from memory.

Reads ELF headers from memory and reconstructs a valid ELF file.
Useful for dumping packed/protected executables after they unpack in memory.

Parameters:
- base_address: Base address where ELF is loaded (must have valid ELF header with magic \\x7fELF)
- output_path: File path to save reconstructed ELF

Returns: {base, output, size, entry, segments, total_segments, architecture}

Process:
1. Reads ELF header at base_address
2. Parses program headers
3. Copies all PT_LOAD segments
4. Writes reconstructed ELF to output_path

Example: unpack.rebuild_elf(base_address="0x400000", output_path="/tmp/unpacked.elf")"""
    )
    async def tool_unpack_rebuild_elf(
        base_address: str, output_path: str
    ) -> Dict[str, Any]:
        return await handlers.unpack_rebuild_elf(base_address, output_path)

    return server


async def run_stdio(log_level: str = "INFO") -> None:
    """Run the MCP server over stdio transport."""
    logging.basicConfig(level=log_level)
    server = build_server()
    await server.run_stdio_async()
