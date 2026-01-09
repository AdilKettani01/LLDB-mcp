from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    import lldb
except Exception:
    lldb = None


class LldbAdapter:
    def __init__(self) -> None:
        if lldb is None:
            raise RuntimeError(
                "lldb module not available. Install LLDB with Python bindings."
            )
        self.debugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(False)
        self.target = None
        self.process = None
        self.selected_thread_id = None

    def close(self) -> None:
        if lldb is None:
            return
        if self.debugger is not None:
            lldb.SBDebugger.Destroy(self.debugger)
            self.debugger = None

    def launch(
        self,
        path: str,
        args: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        raise NotImplementedError("Implement target launch via LLDB SBTarget.")

    def attach(self, pid: int) -> Dict[str, Any]:
        raise NotImplementedError("Implement attach by pid via SBProcess.")

    def detach(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement detach from current process.")

    def kill(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement process kill.")

    def breakpoint_set(
        self,
        location: str,
        condition: Optional[str] = None,
        hardware: bool = False,
    ) -> Dict[str, Any]:
        raise NotImplementedError("Implement breakpoint creation.")

    def breakpoint_clear(self, breakpoint_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement breakpoint clear.")

    def breakpoint_list(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement breakpoint listing.")

    def breakpoint_enable(self, breakpoint_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement breakpoint enable.")

    def breakpoint_disable(self, breakpoint_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement breakpoint disable.")

    def execution_continue(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement continue.")

    def execution_pause(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement pause.")

    def execution_step(self, kind: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement step into, over, or out.")

    def execution_finish(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement finish current function.")

    def registers_read(self, group: Optional[str] = None) -> Dict[str, Any]:
        raise NotImplementedError("Implement register read.")

    def registers_write(self, registers: Dict[str, str]) -> Dict[str, Any]:
        raise NotImplementedError("Implement register write.")

    def memory_read(self, address: str, length: int) -> Dict[str, Any]:
        raise NotImplementedError("Implement memory read.")

    def memory_write(
        self, address: str, data: str, encoding: Optional[str] = None
    ) -> Dict[str, Any]:
        raise NotImplementedError("Implement memory write.")

    def memory_search(
        self,
        address: str,
        length: int,
        pattern: str,
        encoding: Optional[str] = None,
        max_results: int = 10,
    ) -> Dict[str, Any]:
        raise NotImplementedError("Implement memory search.")

    def threads_list(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement thread listing.")

    def thread_select(self, thread_id: int) -> Dict[str, Any]:
        raise NotImplementedError("Implement thread selection.")

    def stack_backtrace(
        self, thread_id: Optional[int] = None, max_frames: int = 64
    ) -> Dict[str, Any]:
        raise NotImplementedError("Implement backtrace.")

    def modules_list(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement module listing.")

    def symbols_resolve(self, query: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement symbol resolve.")

    def memory_map(self) -> Dict[str, Any]:
        raise NotImplementedError("Implement memory map.")

    def unpack_dump_memory(self, start: str, end: str, output_path: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement memory dump.")

    def unpack_rebuild_elf(
        self, base_address: str, output_path: str
    ) -> Dict[str, Any]:
        raise NotImplementedError("Implement ELF rebuild.")
