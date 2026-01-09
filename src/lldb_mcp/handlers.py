from __future__ import annotations

from typing import Any, Dict, List, Optional

from .lldb_adapter import LldbAdapter


class ToolHandlers:
    def __init__(self, adapter: Optional[LldbAdapter] = None) -> None:
        self._adapter = adapter

    def _get_adapter(self) -> LldbAdapter:
        if self._adapter is None:
            self._adapter = LldbAdapter()
        return self._adapter

    async def target_launch(
        self,
        path: str,
        args: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        return self._get_adapter().launch(path, args=args, cwd=cwd, env=env)

    async def target_attach(self, pid: int) -> Dict[str, Any]:
        return self._get_adapter().attach(pid)

    async def target_detach(self) -> Dict[str, Any]:
        return self._get_adapter().detach()

    async def target_kill(self) -> Dict[str, Any]:
        return self._get_adapter().kill()

    async def breakpoint_set(
        self,
        location: str,
        condition: Optional[str] = None,
        hardware: bool = False,
    ) -> Dict[str, Any]:
        return self._get_adapter().breakpoint_set(
            location, condition=condition, hardware=hardware
        )

    async def breakpoint_clear(self, breakpoint_id: str) -> Dict[str, Any]:
        return self._get_adapter().breakpoint_clear(breakpoint_id)

    async def breakpoint_list(self) -> Dict[str, Any]:
        return self._get_adapter().breakpoint_list()

    async def breakpoint_enable(self, breakpoint_id: str) -> Dict[str, Any]:
        return self._get_adapter().breakpoint_enable(breakpoint_id)

    async def breakpoint_disable(self, breakpoint_id: str) -> Dict[str, Any]:
        return self._get_adapter().breakpoint_disable(breakpoint_id)

    async def execution_continue(self) -> Dict[str, Any]:
        return self._get_adapter().execution_continue()

    async def execution_pause(self) -> Dict[str, Any]:
        return self._get_adapter().execution_pause()

    async def execution_step(self, kind: str) -> Dict[str, Any]:
        return self._get_adapter().execution_step(kind)

    async def execution_finish(self) -> Dict[str, Any]:
        return self._get_adapter().execution_finish()

    async def registers_read(self, group: Optional[str] = None) -> Dict[str, Any]:
        return self._get_adapter().registers_read(group=group)

    async def registers_write(self, registers: Dict[str, str]) -> Dict[str, Any]:
        return self._get_adapter().registers_write(registers)

    async def memory_read(self, address: str, length: int) -> Dict[str, Any]:
        return self._get_adapter().memory_read(address, length)

    async def memory_write(
        self, address: str, data: str, encoding: Optional[str] = None
    ) -> Dict[str, Any]:
        return self._get_adapter().memory_write(address, data, encoding=encoding)

    async def memory_search(
        self,
        address: str,
        length: int,
        pattern: str,
        encoding: Optional[str] = None,
        max_results: int = 10,
    ) -> Dict[str, Any]:
        return self._get_adapter().memory_search(
            address,
            length,
            pattern,
            encoding=encoding,
            max_results=max_results,
        )

    async def threads_list(self) -> Dict[str, Any]:
        return self._get_adapter().threads_list()

    async def thread_select(self, thread_id: int) -> Dict[str, Any]:
        return self._get_adapter().thread_select(thread_id)

    async def stack_backtrace(
        self, thread_id: Optional[int] = None, max_frames: int = 64
    ) -> Dict[str, Any]:
        return self._get_adapter().stack_backtrace(
            thread_id=thread_id, max_frames=max_frames
        )

    async def modules_list(self) -> Dict[str, Any]:
        return self._get_adapter().modules_list()

    async def symbols_resolve(self, query: str) -> Dict[str, Any]:
        return self._get_adapter().symbols_resolve(query)

    async def memory_map(self) -> Dict[str, Any]:
        return self._get_adapter().memory_map()

    async def unpack_dump_memory(
        self, start: str, end: str, output_path: str
    ) -> Dict[str, Any]:
        return self._get_adapter().unpack_dump_memory(start, end, output_path)

    async def unpack_rebuild_elf(
        self, base_address: str, output_path: str
    ) -> Dict[str, Any]:
        return self._get_adapter().unpack_rebuild_elf(base_address, output_path)
