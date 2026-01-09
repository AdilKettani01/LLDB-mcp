"""LLDB adapter for MCP server."""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import ServerConfig, default_config
from .errors import (
    BreakpointError,
    InvalidAddressError,
    InvalidOperationError,
    LldbMcpError,
    MemoryAccessError,
    NoProcessError,
    NoTargetError,
    ProcessNotStoppedError,
)
from .utils import bytes_to_hex, format_address, hex_to_bytes, parse_address

try:
    import lldb
except Exception:
    lldb = None


class LldbAdapter:
    """Adapter for LLDB Python bindings."""

    def __init__(self, config: Optional[ServerConfig] = None) -> None:
        """Initialize the LLDB adapter.

        Args:
            config: Server configuration. Uses default if not provided.

        Raises:
            RuntimeError: If LLDB Python bindings are not available.
        """
        if lldb is None:
            raise RuntimeError(
                "lldb module not available. Install LLDB with Python bindings."
            )
        self.config = config or default_config
        self.debugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(self.config.async_mode)
        self.target: Optional[Any] = None
        self.process: Optional[Any] = None
        self.selected_thread_id: Optional[int] = None

    def close(self) -> None:
        """Clean up LLDB resources."""
        if lldb is None:
            return
        if self.process is not None:
            try:
                self.process.Kill()
            except Exception:
                pass
            self.process = None
        if self.debugger is not None:
            lldb.SBDebugger.Destroy(self.debugger)
            self.debugger = None

    # -------------------------------------------------------------------------
    # Helper methods
    # -------------------------------------------------------------------------

    def _ensure_target(self) -> None:
        """Ensure a target exists."""
        if self.target is None or not self.target.IsValid():
            raise NoTargetError("No target has been created")

    def _ensure_process(self) -> None:
        """Ensure a process is attached."""
        if self.process is None or not self.process.IsValid():
            raise NoProcessError("No process is currently being debugged")

    def _ensure_stopped(self) -> None:
        """Ensure process is in stopped state."""
        self._ensure_process()
        state = self.process.GetState()
        if state != lldb.eStateStopped:
            raise ProcessNotStoppedError(
                f"Process is not stopped (state: {self._get_state_name(state)})"
            )

    def _get_selected_thread(self) -> Any:
        """Get the selected thread or first available thread."""
        self._ensure_process()
        if self.selected_thread_id is not None:
            thread = self.process.GetThreadByID(self.selected_thread_id)
            if thread.IsValid():
                return thread
        # Fall back to selected thread or first thread
        thread = self.process.GetSelectedThread()
        if thread.IsValid():
            return thread
        if self.process.GetNumThreads() > 0:
            return self.process.GetThreadAtIndex(0)
        raise NoProcessError("No threads available")

    def _get_state_name(self, state: int) -> str:
        """Convert LLDB state enum to string."""
        state_names = {
            lldb.eStateInvalid: "invalid",
            lldb.eStateUnloaded: "unloaded",
            lldb.eStateConnected: "connected",
            lldb.eStateAttaching: "attaching",
            lldb.eStateLaunching: "launching",
            lldb.eStateStopped: "stopped",
            lldb.eStateRunning: "running",
            lldb.eStateStepping: "stepping",
            lldb.eStateCrashed: "crashed",
            lldb.eStateDetached: "detached",
            lldb.eStateExited: "exited",
            lldb.eStateSuspended: "suspended",
        }
        return state_names.get(state, "unknown")

    def _get_stop_reason(self, thread: Any) -> Dict[str, Any]:
        """Get stop reason info from thread."""
        reason = thread.GetStopReason()
        reason_map = {
            lldb.eStopReasonNone: "none",
            lldb.eStopReasonTrace: "trace",
            lldb.eStopReasonBreakpoint: "breakpoint",
            lldb.eStopReasonWatchpoint: "watchpoint",
            lldb.eStopReasonSignal: "signal",
            lldb.eStopReasonException: "exception",
            lldb.eStopReasonExec: "exec",
            lldb.eStopReasonPlanComplete: "plan_complete",
            lldb.eStopReasonThreadExiting: "thread_exiting",
            lldb.eStopReasonInstrumentation: "instrumentation",
        }
        result = {"reason": reason_map.get(reason, "unknown"), "code": reason}

        # Add extra info for certain stop reasons
        if reason == lldb.eStopReasonBreakpoint:
            bp_id = thread.GetStopReasonDataAtIndex(0)
            result["breakpoint_id"] = bp_id
        elif reason == lldb.eStopReasonSignal:
            signal_num = thread.GetStopReasonDataAtIndex(0)
            result["signal"] = signal_num

        return result

    def _format_frame(self, frame: Any) -> Optional[Dict[str, Any]]:
        """Format SBFrame as dictionary."""
        if frame is None or not frame.IsValid():
            return None

        line_entry = frame.GetLineEntry()
        file_spec = line_entry.GetFileSpec() if line_entry.IsValid() else None

        return {
            "index": frame.GetFrameID(),
            "pc": format_address(frame.GetPC()),
            "sp": format_address(frame.GetSP()),
            "fp": format_address(frame.GetFP()),
            "function": frame.GetFunctionName() or "<unknown>",
            "file": str(file_spec) if file_spec and file_spec.IsValid() else None,
            "line": line_entry.GetLine() if line_entry.IsValid() else None,
            "column": line_entry.GetColumn() if line_entry.IsValid() else None,
            "module": (
                frame.GetModule().GetFileSpec().GetFilename()
                if frame.GetModule().IsValid()
                else None
            ),
        }

    def _parse_breakpoint_location(
        self, location: str
    ) -> Tuple[str, Any]:
        """Parse breakpoint location string.

        Returns:
            Tuple of (type, value) where type is "address", "location", or "name"
        """
        location = location.strip()

        # Check for address: 0x prefix or all hex digits (8+)
        if location.startswith("0x") or location.startswith("0X"):
            return ("address", parse_address(location))
        if re.match(r"^[0-9a-fA-F]{8,}$", location):
            return ("address", parse_address(location))

        # Check for file:line format
        if ":" in location:
            parts = location.rsplit(":", 1)
            if parts[-1].isdigit():
                return ("location", (parts[0], int(parts[1])))

        # Default to symbol name
        return ("name", location)

    # -------------------------------------------------------------------------
    # Target management
    # -------------------------------------------------------------------------

    def launch(
        self,
        path: str,
        args: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Launch a target process.

        Args:
            path: Path to executable
            args: Command line arguments
            cwd: Working directory
            env: Environment variables

        Returns:
            Dictionary with pid, state, and path
        """
        # Validate path
        exe_path = Path(path).resolve()
        if not exe_path.exists():
            raise LldbMcpError(f"Executable not found: {path}")
        if not exe_path.is_file():
            raise LldbMcpError(f"Path is not a file: {path}")

        # Create target
        error = lldb.SBError()
        self.target = self.debugger.CreateTarget(
            str(exe_path), None, None, True, error
        )
        if not self.target or not self.target.IsValid():
            raise LldbMcpError(f"Failed to create target: {error.GetCString()}")

        # Build environment list
        env_list = None
        if env:
            env_list = [f"{k}={v}" for k, v in env.items()]

        # Launch process
        launch_info = lldb.SBLaunchInfo(args or [])
        if cwd:
            launch_info.SetWorkingDirectory(cwd)
        if env_list:
            launch_info.SetEnvironmentEntries(env_list, True)

        error = lldb.SBError()
        self.process = self.target.Launch(launch_info, error)

        if not error.Success():
            raise LldbMcpError(f"Failed to launch process: {error.GetCString()}")

        if self.process is None or not self.process.IsValid():
            raise LldbMcpError("Process launch returned invalid process")

        state = self.process.GetState()
        return {
            "pid": self.process.GetProcessID(),
            "state": self._get_state_name(state),
            "path": str(exe_path),
        }

    def attach(self, pid: int) -> Dict[str, Any]:
        """Attach to a process by PID.

        Args:
            pid: Process ID to attach to

        Returns:
            Dictionary with pid, state, and attached status
        """
        # Create empty target if none exists
        if self.target is None or not self.target.IsValid():
            self.target = self.debugger.CreateTarget("")

        error = lldb.SBError()
        self.process = self.target.AttachToProcessWithID(
            lldb.SBListener(), pid, error
        )

        if not error.Success():
            raise LldbMcpError(f"Failed to attach to process {pid}: {error.GetCString()}")

        if self.process is None or not self.process.IsValid():
            raise LldbMcpError(f"Attach returned invalid process for pid {pid}")

        state = self.process.GetState()
        return {
            "pid": pid,
            "state": self._get_state_name(state),
            "attached": True,
        }

    def detach(self) -> Dict[str, Any]:
        """Detach from the current process.

        Returns:
            Dictionary with detached status
        """
        self._ensure_process()

        error = self.process.Detach()
        if not error.Success():
            raise LldbMcpError(f"Failed to detach: {error.GetCString()}")

        self.process = None
        self.selected_thread_id = None

        return {"detached": True}

    def kill(self) -> Dict[str, Any]:
        """Kill the current process.

        Returns:
            Dictionary with killed status and exit code
        """
        self._ensure_process()

        error = self.process.Kill()
        if not error.Success():
            raise LldbMcpError(f"Failed to kill process: {error.GetCString()}")

        exit_status = self.process.GetExitStatus()
        self.process = None
        self.selected_thread_id = None

        return {"killed": True, "exit_code": exit_status}

    # -------------------------------------------------------------------------
    # Breakpoint management
    # -------------------------------------------------------------------------

    def breakpoint_set(
        self,
        location: str,
        condition: Optional[str] = None,
        hardware: bool = False,
    ) -> Dict[str, Any]:
        """Set a breakpoint.

        Args:
            location: Breakpoint location (address, symbol name, or file:line)
            condition: Optional condition expression
            hardware: Request hardware breakpoint

        Returns:
            Dictionary with breakpoint id and locations
        """
        self._ensure_target()

        loc_type, loc_value = self._parse_breakpoint_location(location)

        if loc_type == "address":
            bp = self.target.BreakpointCreateByAddress(loc_value)
        elif loc_type == "location":
            file_path, line = loc_value
            bp = self.target.BreakpointCreateByLocation(file_path, line)
        else:  # name
            bp = self.target.BreakpointCreateByName(loc_value)

        if not bp.IsValid():
            raise BreakpointError(f"Failed to create breakpoint at {location}")

        if bp.GetNumLocations() == 0:
            # Breakpoint created but not resolved - could be pending
            pass

        if condition:
            bp.SetCondition(condition)

        # Note: Hardware breakpoints depend on target support
        # LLDB will automatically use hardware if available and requested

        # Get location addresses
        locations = []
        for i in range(bp.GetNumLocations()):
            loc = bp.GetLocationAtIndex(i)
            addr = loc.GetAddress()
            locations.append({
                "address": format_address(addr.GetLoadAddress(self.target)),
                "resolved": loc.IsResolved(),
            })

        return {
            "id": bp.GetID(),
            "locations": bp.GetNumLocations(),
            "location_details": locations,
            "enabled": bp.IsEnabled(),
            "condition": condition,
        }

    def breakpoint_clear(self, breakpoint_id: str) -> Dict[str, Any]:
        """Clear a breakpoint.

        Args:
            breakpoint_id: Breakpoint ID to clear

        Returns:
            Dictionary with deleted status
        """
        self._ensure_target()

        try:
            bp_id = int(breakpoint_id)
        except ValueError:
            raise BreakpointError(f"Invalid breakpoint ID: {breakpoint_id}")

        success = self.target.BreakpointDelete(bp_id)

        return {"deleted": success, "id": breakpoint_id}

    def breakpoint_list(self) -> Dict[str, Any]:
        """List all breakpoints.

        Returns:
            Dictionary with breakpoints list
        """
        self._ensure_target()

        breakpoints = []
        for i in range(self.target.GetNumBreakpoints()):
            bp = self.target.GetBreakpointAtIndex(i)

            locations = []
            for j in range(bp.GetNumLocations()):
                loc = bp.GetLocationAtIndex(j)
                addr = loc.GetAddress()
                locations.append({
                    "address": format_address(addr.GetLoadAddress(self.target)),
                    "resolved": loc.IsResolved(),
                    "enabled": loc.IsEnabled(),
                })

            breakpoints.append({
                "id": bp.GetID(),
                "enabled": bp.IsEnabled(),
                "hit_count": bp.GetHitCount(),
                "condition": bp.GetCondition() or None,
                "locations": locations,
                "num_locations": bp.GetNumLocations(),
            })

        return {"breakpoints": breakpoints, "count": len(breakpoints)}

    def breakpoint_enable(self, breakpoint_id: str) -> Dict[str, Any]:
        """Enable a breakpoint.

        Args:
            breakpoint_id: Breakpoint ID to enable

        Returns:
            Dictionary with enabled status
        """
        self._ensure_target()

        try:
            bp_id = int(breakpoint_id)
        except ValueError:
            raise BreakpointError(f"Invalid breakpoint ID: {breakpoint_id}")

        bp = self.target.FindBreakpointByID(bp_id)
        if not bp.IsValid():
            raise BreakpointError(f"Breakpoint {breakpoint_id} not found")

        bp.SetEnabled(True)

        return {"id": breakpoint_id, "enabled": True}

    def breakpoint_disable(self, breakpoint_id: str) -> Dict[str, Any]:
        """Disable a breakpoint.

        Args:
            breakpoint_id: Breakpoint ID to disable

        Returns:
            Dictionary with disabled status
        """
        self._ensure_target()

        try:
            bp_id = int(breakpoint_id)
        except ValueError:
            raise BreakpointError(f"Invalid breakpoint ID: {breakpoint_id}")

        bp = self.target.FindBreakpointByID(bp_id)
        if not bp.IsValid():
            raise BreakpointError(f"Breakpoint {breakpoint_id} not found")

        bp.SetEnabled(False)

        return {"id": breakpoint_id, "enabled": False}

    # -------------------------------------------------------------------------
    # Execution control
    # -------------------------------------------------------------------------

    def execution_continue(self) -> Dict[str, Any]:
        """Continue execution.

        Returns:
            Dictionary with state and thread info
        """
        self._ensure_stopped()

        error = self.process.Continue()
        if not error.Success():
            raise LldbMcpError(f"Continue failed: {error.GetCString()}")

        state = self.process.GetState()
        result = {"state": self._get_state_name(state)}

        if state == lldb.eStateStopped:
            thread = self.process.GetSelectedThread()
            if thread.IsValid():
                result["thread_id"] = thread.GetThreadID()
                result["stop_reason"] = self._get_stop_reason(thread)
                result["frame"] = self._format_frame(thread.GetFrameAtIndex(0))

        return result

    def execution_pause(self) -> Dict[str, Any]:
        """Pause execution.

        Returns:
            Dictionary with state
        """
        self._ensure_process()

        state = self.process.GetState()
        if state == lldb.eStateStopped:
            return {"state": "stopped", "message": "Already stopped"}

        error = self.process.Stop()
        if not error.Success():
            raise LldbMcpError(f"Pause failed: {error.GetCString()}")

        state = self.process.GetState()
        return {"state": self._get_state_name(state)}

    def execution_step(self, kind: str) -> Dict[str, Any]:
        """Step execution.

        Args:
            kind: Step type - "into", "over", "out", or "instruction"

        Returns:
            Dictionary with state and frame info
        """
        self._ensure_stopped()
        thread = self._get_selected_thread()

        kind = kind.lower().strip()
        if kind == "into":
            thread.StepInto()
        elif kind == "over":
            thread.StepOver()
        elif kind == "out":
            thread.StepOut()
        elif kind == "instruction":
            thread.StepInstruction(False)  # step_over=False for step into
        else:
            raise InvalidOperationError(
                f"Invalid step kind: {kind}. Use: into, over, out, instruction"
            )

        state = self.process.GetState()
        frame = thread.GetFrameAtIndex(0)

        return {
            "state": self._get_state_name(state),
            "thread_id": thread.GetThreadID(),
            "frame": self._format_frame(frame),
            "stop_reason": self._get_stop_reason(thread),
        }

    def execution_finish(self) -> Dict[str, Any]:
        """Finish current function (step out).

        Returns:
            Dictionary with state and frame info
        """
        self._ensure_stopped()
        thread = self._get_selected_thread()

        thread.StepOut()

        state = self.process.GetState()
        frame = thread.GetFrameAtIndex(0)

        return {
            "state": self._get_state_name(state),
            "thread_id": thread.GetThreadID(),
            "frame": self._format_frame(frame),
            "stop_reason": self._get_stop_reason(thread),
        }

    # -------------------------------------------------------------------------
    # Register operations
    # -------------------------------------------------------------------------

    def registers_read(self, group: Optional[str] = None) -> Dict[str, Any]:
        """Read registers.

        Args:
            group: Optional register group filter (e.g., "general", "floating")

        Returns:
            Dictionary with registers by group
        """
        self._ensure_stopped()
        thread = self._get_selected_thread()
        frame = thread.GetFrameAtIndex(0)

        if not frame.IsValid():
            raise LldbMcpError("No valid frame for register access")

        register_sets = frame.GetRegisters()
        result = {}

        for reg_set in register_sets:
            set_name = reg_set.GetName()

            # Filter by group if specified
            if group and group.lower() not in set_name.lower():
                continue

            registers = {}
            for reg in reg_set:
                value = reg.GetValue()
                if value is not None:
                    registers[reg.GetName()] = value

            if registers:
                result[set_name] = registers

        return {"registers": result, "thread_id": thread.GetThreadID()}

    def registers_write(self, registers: Dict[str, str]) -> Dict[str, Any]:
        """Write registers.

        Args:
            registers: Dictionary of register name to value

        Returns:
            Dictionary with results for each register
        """
        self._ensure_stopped()
        thread = self._get_selected_thread()
        frame = thread.GetFrameAtIndex(0)

        if not frame.IsValid():
            raise LldbMcpError("No valid frame for register access")

        results = {}
        for name, value in registers.items():
            reg = frame.FindRegister(name)
            if not reg.IsValid():
                results[name] = {"success": False, "error": "Register not found"}
                continue

            success = reg.SetValueFromCString(value)
            results[name] = {
                "success": success,
                "new_value": reg.GetValue() if success else None,
                "error": None if success else "Failed to set value",
            }

        return {"results": results, "thread_id": thread.GetThreadID()}

    # -------------------------------------------------------------------------
    # Memory operations
    # -------------------------------------------------------------------------

    def memory_read(self, address: str, length: int) -> Dict[str, Any]:
        """Read memory.

        Args:
            address: Start address (hex or decimal)
            length: Number of bytes to read

        Returns:
            Dictionary with hex data and ASCII representation
        """
        self._ensure_process()

        try:
            addr = parse_address(address)
        except ValueError as e:
            raise InvalidAddressError(str(e))

        if length <= 0:
            raise MemoryAccessError("Length must be positive")
        if length > self.config.max_memory_read_size:
            raise MemoryAccessError(
                f"Length {length} exceeds maximum {self.config.max_memory_read_size}"
            )

        error = lldb.SBError()
        data = self.process.ReadMemory(addr, length, error)

        if not error.Success():
            raise MemoryAccessError(f"Memory read failed: {error.GetCString()}")

        if data is None:
            raise MemoryAccessError(f"Memory read returned no data at {address}")

        # Generate ASCII representation
        ascii_repr = ""
        for byte in data:
            if 32 <= byte < 127:
                ascii_repr += chr(byte)
            else:
                ascii_repr += "."

        return {
            "address": format_address(addr),
            "length": len(data),
            "data": bytes_to_hex(data),
            "ascii": ascii_repr,
        }

    def memory_write(
        self, address: str, data: str, encoding: Optional[str] = None
    ) -> Dict[str, Any]:
        """Write memory.

        Args:
            address: Start address (hex or decimal)
            data: Data to write
            encoding: Data encoding - "hex" (default), "ascii", or "utf8"

        Returns:
            Dictionary with bytes written
        """
        self._ensure_process()

        try:
            addr = parse_address(address)
        except ValueError as e:
            raise InvalidAddressError(str(e))

        # Parse data based on encoding
        encoding = encoding or "hex"
        try:
            if encoding == "hex":
                buf = hex_to_bytes(data)
            elif encoding == "ascii":
                buf = data.encode("ascii")
            elif encoding == "utf8" or encoding == "utf-8":
                buf = data.encode("utf-8")
            else:
                raise LldbMcpError(f"Unknown encoding: {encoding}")
        except Exception as e:
            raise LldbMcpError(f"Failed to encode data: {e}")

        if len(buf) > self.config.max_memory_write_size:
            raise MemoryAccessError(
                f"Data size {len(buf)} exceeds maximum {self.config.max_memory_write_size}"
            )

        error = lldb.SBError()
        bytes_written = self.process.WriteMemory(addr, buf, error)

        if not error.Success():
            raise MemoryAccessError(f"Memory write failed: {error.GetCString()}")

        return {
            "address": format_address(addr),
            "bytes_written": bytes_written,
            "success": bytes_written == len(buf),
        }

    def memory_search(
        self,
        address: str,
        length: int,
        pattern: str,
        encoding: Optional[str] = None,
        max_results: int = 10,
    ) -> Dict[str, Any]:
        """Search memory for a pattern.

        Args:
            address: Start address
            length: Number of bytes to search
            pattern: Pattern to search for
            encoding: Pattern encoding - "hex" (default), "ascii", or "utf8"
            max_results: Maximum number of results to return

        Returns:
            Dictionary with match addresses
        """
        self._ensure_process()

        try:
            start_addr = parse_address(address)
        except ValueError as e:
            raise InvalidAddressError(str(e))

        # Parse pattern
        encoding = encoding or "hex"
        try:
            if encoding == "hex":
                search_bytes = hex_to_bytes(pattern)
            elif encoding == "ascii":
                search_bytes = pattern.encode("ascii")
            else:
                search_bytes = pattern.encode("utf-8")
        except Exception as e:
            raise LldbMcpError(f"Failed to encode pattern: {e}")

        if len(search_bytes) == 0:
            raise LldbMcpError("Empty search pattern")

        # Read memory in chunks and search
        chunk_size = 4096
        results = []
        current_addr = start_addr
        end_addr = start_addr + length
        overlap = len(search_bytes) - 1
        prev_tail = b""

        while current_addr < end_addr and len(results) < max_results:
            read_size = min(chunk_size, end_addr - current_addr)
            error = lldb.SBError()
            chunk = self.process.ReadMemory(current_addr, read_size, error)

            if not error.Success() or not chunk:
                current_addr += chunk_size
                prev_tail = b""
                continue

            # Combine with previous tail for patterns spanning chunks
            search_data = prev_tail + chunk
            search_offset = len(prev_tail)

            # Search for pattern
            offset = 0
            while offset < len(search_data) and len(results) < max_results:
                pos = search_data.find(search_bytes, offset)
                if pos == -1:
                    break
                # Calculate actual address
                actual_addr = current_addr - search_offset + pos
                if actual_addr >= start_addr:
                    results.append(format_address(actual_addr))
                offset = pos + 1

            # Keep tail for next iteration
            prev_tail = chunk[-overlap:] if overlap > 0 else b""
            current_addr += read_size

        return {
            "pattern": pattern,
            "encoding": encoding,
            "matches": results,
            "count": len(results),
            "truncated": len(results) >= max_results,
        }

    # -------------------------------------------------------------------------
    # Thread and stack operations
    # -------------------------------------------------------------------------

    def threads_list(self) -> Dict[str, Any]:
        """List all threads.

        Returns:
            Dictionary with thread list
        """
        self._ensure_process()

        threads = []
        selected_thread = self.process.GetSelectedThread()
        selected_id = selected_thread.GetThreadID() if selected_thread.IsValid() else None

        for i in range(self.process.GetNumThreads()):
            thread = self.process.GetThreadAtIndex(i)
            frame = thread.GetFrameAtIndex(0) if thread.GetNumFrames() > 0 else None

            threads.append({
                "id": thread.GetThreadID(),
                "index": i,
                "name": thread.GetName() or f"Thread {thread.GetThreadID()}",
                "queue": thread.GetQueueName() or None,
                "selected": thread.GetThreadID() == selected_id,
                "num_frames": thread.GetNumFrames(),
                "stop_reason": self._get_stop_reason(thread),
                "frame": self._format_frame(frame) if frame else None,
            })

        return {"threads": threads, "count": len(threads)}

    def thread_select(self, thread_id: int) -> Dict[str, Any]:
        """Select a thread.

        Args:
            thread_id: Thread ID to select

        Returns:
            Dictionary with selected thread info
        """
        self._ensure_process()

        success = self.process.SetSelectedThreadByID(thread_id)
        if not success:
            raise LldbMcpError(f"Thread {thread_id} not found")

        self.selected_thread_id = thread_id
        thread = self.process.GetSelectedThread()

        return {
            "selected": thread_id,
            "name": thread.GetName(),
            "num_frames": thread.GetNumFrames(),
            "frame": (
                self._format_frame(thread.GetFrameAtIndex(0))
                if thread.GetNumFrames() > 0
                else None
            ),
        }

    def stack_backtrace(
        self, thread_id: Optional[int] = None, max_frames: int = 64
    ) -> Dict[str, Any]:
        """Get stack backtrace.

        Args:
            thread_id: Thread ID (uses selected thread if not specified)
            max_frames: Maximum number of frames to return

        Returns:
            Dictionary with frames list
        """
        self._ensure_stopped()

        if thread_id is not None:
            thread = self.process.GetThreadByID(thread_id)
            if not thread.IsValid():
                raise LldbMcpError(f"Thread {thread_id} not found")
        else:
            thread = self._get_selected_thread()

        frames = []
        num_frames = min(thread.GetNumFrames(), max_frames)

        for i in range(num_frames):
            frame = thread.GetFrameAtIndex(i)
            frames.append(self._format_frame(frame))

        return {
            "thread_id": thread.GetThreadID(),
            "frames": frames,
            "count": num_frames,
            "total_frames": thread.GetNumFrames(),
            "truncated": thread.GetNumFrames() > max_frames,
        }

    # -------------------------------------------------------------------------
    # Module and symbol operations
    # -------------------------------------------------------------------------

    def modules_list(self) -> Dict[str, Any]:
        """List loaded modules.

        Returns:
            Dictionary with module list
        """
        self._ensure_target()

        modules = []
        for i in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(i)
            file_spec = module.GetFileSpec()

            # Get sections
            sections = []
            for j in range(module.GetNumSections()):
                section = module.GetSectionAtIndex(j)
                load_addr = section.GetLoadAddress(self.target)
                sections.append({
                    "name": section.GetName(),
                    "address": format_address(load_addr) if load_addr != 0xFFFFFFFFFFFFFFFF else None,
                    "size": section.GetByteSize(),
                    "file_offset": section.GetFileOffset(),
                    "type": str(section.GetSectionType()),
                })

            modules.append({
                "name": file_spec.GetFilename(),
                "path": str(file_spec),
                "uuid": module.GetUUIDString(),
                "num_sections": module.GetNumSections(),
                "sections": sections,
                "num_symbols": module.GetNumSymbols(),
            })

        return {"modules": modules, "count": len(modules)}

    def symbols_resolve(self, query: str) -> Dict[str, Any]:
        """Resolve a symbol.

        Args:
            query: Symbol name or address to resolve

        Returns:
            Dictionary with matching symbols
        """
        self._ensure_target()

        results = []

        # Check if query is an address
        is_address = query.startswith("0x") or re.match(r"^[0-9a-fA-F]{8,}$", query)

        if is_address:
            try:
                addr = parse_address(query)
                sb_addr = self.target.ResolveLoadAddress(addr)
                if sb_addr.IsValid():
                    symbol = sb_addr.GetSymbol()
                    if symbol.IsValid():
                        start_addr = symbol.GetStartAddress()
                        end_addr = symbol.GetEndAddress()
                        results.append({
                            "name": symbol.GetName(),
                            "mangled_name": symbol.GetMangledName(),
                            "address": (
                                format_address(start_addr.GetLoadAddress(self.target))
                                if start_addr.IsValid()
                                else None
                            ),
                            "size": (
                                end_addr.GetLoadAddress(self.target) - start_addr.GetLoadAddress(self.target)
                                if start_addr.IsValid() and end_addr.IsValid()
                                else None
                            ),
                            "type": "symbol",
                        })
                    # Also try to get function info
                    func = sb_addr.GetFunction()
                    if func.IsValid() and (not symbol.IsValid() or func.GetName() != symbol.GetName()):
                        results.append({
                            "name": func.GetName(),
                            "mangled_name": func.GetMangledName(),
                            "address": format_address(func.GetStartAddress().GetLoadAddress(self.target)),
                            "type": "function",
                        })
            except ValueError:
                pass
        else:
            # Search by name
            symbol_contexts = self.target.FindSymbols(query)
            for i in range(min(symbol_contexts.GetSize(), 100)):  # Limit results
                ctx = symbol_contexts.GetContextAtIndex(i)
                symbol = ctx.GetSymbol()
                if symbol.IsValid():
                    start_addr = symbol.GetStartAddress()
                    results.append({
                        "name": symbol.GetName(),
                        "mangled_name": symbol.GetMangledName(),
                        "address": (
                            format_address(start_addr.GetLoadAddress(self.target))
                            if start_addr.IsValid()
                            else None
                        ),
                        "module": (
                            ctx.GetModule().GetFileSpec().GetFilename()
                            if ctx.GetModule().IsValid()
                            else None
                        ),
                        "type": "symbol",
                    })

        return {"query": query, "symbols": results, "count": len(results)}

    def memory_map(self) -> Dict[str, Any]:
        """Get memory map.

        Returns:
            Dictionary with memory regions
        """
        self._ensure_process()

        regions_list = self.process.GetMemoryRegions()
        regions = []

        for i in range(regions_list.GetSize()):
            region = lldb.SBMemoryRegionInfo()
            if regions_list.GetMemoryRegionAtIndex(i, region):
                base = region.GetRegionBase()
                end = region.GetRegionEnd()

                # Build permission string
                perms = ""
                perms += "r" if region.IsReadable() else "-"
                perms += "w" if region.IsWritable() else "-"
                perms += "x" if region.IsExecutable() else "-"

                regions.append({
                    "start": format_address(base),
                    "end": format_address(end),
                    "size": end - base,
                    "permissions": perms,
                    "readable": region.IsReadable(),
                    "writable": region.IsWritable(),
                    "executable": region.IsExecutable(),
                    "name": region.GetName() or None,
                    "mapped": region.IsMapped(),
                })

        return {"regions": regions, "count": len(regions)}

    # -------------------------------------------------------------------------
    # ELF unpacking operations
    # -------------------------------------------------------------------------

    def unpack_dump_memory(
        self, start: str, end: str, output_path: str
    ) -> Dict[str, Any]:
        """Dump a memory range to file.

        Args:
            start: Start address
            end: End address
            output_path: Output file path

        Returns:
            Dictionary with dump metadata
        """
        self._ensure_process()

        # Validate output path
        output = Path(output_path).resolve()
        self.config.validate_output_path(output)

        try:
            start_addr = parse_address(start)
            end_addr = parse_address(end)
        except ValueError as e:
            raise InvalidAddressError(str(e))

        if end_addr <= start_addr:
            raise LldbMcpError("End address must be greater than start address")

        # Read memory in chunks
        chunk_size = 1024 * 1024  # 1MB chunks
        data = bytearray()
        current = start_addr
        errors = []

        while current < end_addr:
            read_size = min(chunk_size, end_addr - current)
            error = lldb.SBError()
            chunk = self.process.ReadMemory(current, read_size, error)

            if error.Success() and chunk:
                data.extend(chunk)
            else:
                # Fill with zeros for unmapped regions
                data.extend(b"\x00" * read_size)
                errors.append({
                    "address": format_address(current),
                    "size": read_size,
                    "error": error.GetCString() if not error.Success() else "No data",
                })

            current += read_size

        # Ensure parent directory exists
        output.parent.mkdir(parents=True, exist_ok=True)

        # Write to file
        output.write_bytes(bytes(data))

        # Create metadata
        metadata = {
            "start": format_address(start_addr),
            "end": format_address(end_addr),
            "size": len(data),
            "hash_sha256": hashlib.sha256(data).hexdigest(),
            "hash_md5": hashlib.md5(data).hexdigest(),
            "output": str(output),
            "errors": errors if errors else None,
        }

        # Write metadata JSON
        metadata_path = output.with_suffix(output.suffix + ".meta.json")
        metadata_path.write_text(json.dumps(metadata, indent=2))

        return metadata

    def unpack_rebuild_elf(
        self, base_address: str, output_path: str
    ) -> Dict[str, Any]:
        """Rebuild an ELF from memory.

        Args:
            base_address: Base address of ELF in memory
            output_path: Output file path

        Returns:
            Dictionary with rebuild results
        """
        self._ensure_process()

        # Validate output path
        output = Path(output_path).resolve()
        self.config.validate_output_path(output)

        try:
            base = parse_address(base_address)
        except ValueError as e:
            raise InvalidAddressError(str(e))

        # Step 1: Read ELF header
        error = lldb.SBError()
        elf_header = self.process.ReadMemory(base, 64, error)

        if not error.Success() or not elf_header:
            raise MemoryAccessError(f"Cannot read ELF header at {base_address}")

        # Validate ELF magic
        if elf_header[:4] != b"\x7fELF":
            raise LldbMcpError(f"Invalid ELF magic at base address {base_address}")

        # Step 2: Parse ELF header
        ei_class = elf_header[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = elf_header[5]   # 1 = little endian, 2 = big endian

        if ei_class != 2:
            raise LldbMcpError("Only 64-bit ELF supported")

        fmt = "<" if ei_data == 1 else ">"

        # Parse header fields
        e_type, e_machine = struct.unpack(fmt + "HH", elf_header[16:20])
        e_entry = struct.unpack(fmt + "Q", elf_header[24:32])[0]
        e_phoff = struct.unpack(fmt + "Q", elf_header[32:40])[0]
        _e_shoff = struct.unpack(fmt + "Q", elf_header[40:48])[0]  # noqa: F841
        e_phentsize, e_phnum = struct.unpack(fmt + "HH", elf_header[54:58])
        _e_shentsize, _e_shnum = struct.unpack(fmt + "HH", elf_header[58:62])  # noqa: F841

        # Step 3: Read program headers
        phdr_size = e_phentsize * e_phnum
        phdrs = self.process.ReadMemory(base + e_phoff, phdr_size, error)

        if not error.Success() or not phdrs:
            raise MemoryAccessError("Cannot read program headers")

        # Step 4: Parse program headers and find PT_LOAD segments
        segments = []
        PT_LOAD = 1

        for i in range(e_phnum):
            offset = i * e_phentsize
            phdr = phdrs[offset:offset + e_phentsize]

            p_type = struct.unpack(fmt + "I", phdr[0:4])[0]
            p_flags = struct.unpack(fmt + "I", phdr[4:8])[0]
            p_offset = struct.unpack(fmt + "Q", phdr[8:16])[0]
            p_vaddr = struct.unpack(fmt + "Q", phdr[16:24])[0]
            p_paddr = struct.unpack(fmt + "Q", phdr[24:32])[0]
            p_filesz = struct.unpack(fmt + "Q", phdr[32:40])[0]
            p_memsz = struct.unpack(fmt + "Q", phdr[40:48])[0]

            segments.append({
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "paddr": p_paddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
            })

        # Step 5: Calculate total size needed
        load_segments = [s for s in segments if s["type"] == PT_LOAD]
        if not load_segments:
            raise LldbMcpError("No PT_LOAD segments found")

        # Find the extent of all loadable segments
        min_vaddr = min(s["vaddr"] for s in load_segments)
        max_vaddr = max(s["vaddr"] + s["memsz"] for s in load_segments)
        total_size = max_vaddr - min_vaddr

        # Step 6: Create output buffer
        output_data = bytearray(total_size)

        # Step 7: Copy each PT_LOAD segment
        for seg in load_segments:
            offset = seg["vaddr"] - min_vaddr
            seg_data = self.process.ReadMemory(seg["vaddr"], seg["memsz"], error)

            if error.Success() and seg_data:
                output_data[offset:offset + len(seg_data)] = seg_data

        # Ensure parent directory exists
        output.parent.mkdir(parents=True, exist_ok=True)

        # Step 8: Write output
        output.write_bytes(bytes(output_data))

        return {
            "base": format_address(base),
            "output": str(output),
            "size": total_size,
            "entry": format_address(e_entry),
            "segments": len(load_segments),
            "total_segments": len(segments),
            "architecture": "x86_64" if e_machine == 62 else f"machine_{e_machine}",
        }
