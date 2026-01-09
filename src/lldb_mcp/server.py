from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .handlers import ToolHandlers

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
except Exception:
    Server = None
    stdio_server = None


def build_server() -> "Server":
    if Server is None or stdio_server is None:
        raise RuntimeError(
            "mcp package not available. Install the MCP Python library and retry."
        )

    server = Server("lldb-mcp")
    handlers = ToolHandlers()

    @server.tool(name="target.launch", description="Launch a target process.")
    async def tool_target_launch(
        path: str,
        args: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        return await handlers.target_launch(path, args=args, cwd=cwd, env=env)

    @server.tool(name="target.attach", description="Attach to a process by pid.")
    async def tool_target_attach(pid: int) -> Dict[str, Any]:
        return await handlers.target_attach(pid)

    @server.tool(name="target.detach", description="Detach from the current target.")
    async def tool_target_detach() -> Dict[str, Any]:
        return await handlers.target_detach()

    @server.tool(name="target.kill", description="Kill the current target process.")
    async def tool_target_kill() -> Dict[str, Any]:
        return await handlers.target_kill()

    @server.tool(name="breakpoint.set", description="Set a breakpoint.")
    async def tool_breakpoint_set(
        location: str,
        condition: Optional[str] = None,
        hardware: bool = False,
    ) -> Dict[str, Any]:
        return await handlers.breakpoint_set(
            location, condition=condition, hardware=hardware
        )

    @server.tool(name="breakpoint.clear", description="Clear a breakpoint.")
    async def tool_breakpoint_clear(breakpoint_id: str) -> Dict[str, Any]:
        return await handlers.breakpoint_clear(breakpoint_id)

    @server.tool(name="breakpoint.list", description="List breakpoints.")
    async def tool_breakpoint_list() -> Dict[str, Any]:
        return await handlers.breakpoint_list()

    @server.tool(name="breakpoint.enable", description="Enable a breakpoint.")
    async def tool_breakpoint_enable(breakpoint_id: str) -> Dict[str, Any]:
        return await handlers.breakpoint_enable(breakpoint_id)

    @server.tool(name="breakpoint.disable", description="Disable a breakpoint.")
    async def tool_breakpoint_disable(breakpoint_id: str) -> Dict[str, Any]:
        return await handlers.breakpoint_disable(breakpoint_id)

    @server.tool(name="execution.continue", description="Continue execution.")
    async def tool_execution_continue() -> Dict[str, Any]:
        return await handlers.execution_continue()

    @server.tool(name="execution.pause", description="Pause execution.")
    async def tool_execution_pause() -> Dict[str, Any]:
        return await handlers.execution_pause()

    @server.tool(
        name="execution.step",
        description="Step execution. kind is into, over, or out.",
    )
    async def tool_execution_step(kind: str) -> Dict[str, Any]:
        return await handlers.execution_step(kind)

    @server.tool(name="execution.finish", description="Finish current function.")
    async def tool_execution_finish() -> Dict[str, Any]:
        return await handlers.execution_finish()

    @server.tool(name="registers.read", description="Read registers.")
    async def tool_registers_read(group: Optional[str] = None) -> Dict[str, Any]:
        return await handlers.registers_read(group=group)

    @server.tool(name="registers.write", description="Write registers.")
    async def tool_registers_write(registers: Dict[str, str]) -> Dict[str, Any]:
        return await handlers.registers_write(registers)

    @server.tool(name="memory.read", description="Read memory.")
    async def tool_memory_read(address: str, length: int) -> Dict[str, Any]:
        return await handlers.memory_read(address, length)

    @server.tool(name="memory.write", description="Write memory.")
    async def tool_memory_write(
        address: str, data: str, encoding: Optional[str] = None
    ) -> Dict[str, Any]:
        return await handlers.memory_write(address, data, encoding=encoding)

    @server.tool(name="memory.search", description="Search memory.")
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

    @server.tool(name="threads.list", description="List threads.")
    async def tool_threads_list() -> Dict[str, Any]:
        return await handlers.threads_list()

    @server.tool(name="thread.select", description="Select a thread by id.")
    async def tool_thread_select(thread_id: int) -> Dict[str, Any]:
        return await handlers.thread_select(thread_id)

    @server.tool(name="stack.backtrace", description="Get a backtrace.")
    async def tool_stack_backtrace(
        thread_id: Optional[int] = None, max_frames: int = 64
    ) -> Dict[str, Any]:
        return await handlers.stack_backtrace(
            thread_id=thread_id, max_frames=max_frames
        )

    @server.tool(name="modules.list", description="List loaded modules.")
    async def tool_modules_list() -> Dict[str, Any]:
        return await handlers.modules_list()

    @server.tool(name="symbols.resolve", description="Resolve a symbol.")
    async def tool_symbols_resolve(query: str) -> Dict[str, Any]:
        return await handlers.symbols_resolve(query)

    @server.tool(name="memory.map", description="Return memory map.")
    async def tool_memory_map() -> Dict[str, Any]:
        return await handlers.memory_map()

    @server.tool(name="unpack.dump_memory", description="Dump a memory range.")
    async def tool_unpack_dump_memory(
        start: str, end: str, output_path: str
    ) -> Dict[str, Any]:
        return await handlers.unpack_dump_memory(start, end, output_path)

    @server.tool(
        name="unpack.rebuild_elf", description="Rebuild an ELF from memory."
    )
    async def tool_unpack_rebuild_elf(
        base_address: str, output_path: str
    ) -> Dict[str, Any]:
        return await handlers.unpack_rebuild_elf(base_address, output_path)

    return server


async def run_stdio(log_level: str = "INFO") -> None:
    logging.basicConfig(level=log_level)
    server = build_server()
    async with stdio_server() as (read, write):
        await server.run(
            read, write, initialization_options={"server_name": "lldb-mcp"}
        )
