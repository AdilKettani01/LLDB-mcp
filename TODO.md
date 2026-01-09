# TODO

## Project definition
<<<<<<< HEAD
- [ ] Confirm MCP protocol and Python library choice (or implement custom JSON-RPC).
- [ ] Decide transport default (stdio) and optional transports (TCP, WebSocket).
- [ ] Define supported LLDB versions and Python runtime constraints.
- [ ] Establish logging, tracing, and telemetry strategy.
- [ ] Define tool naming conventions and stable error codes.

## Core server scaffolding
- [ ] Implement MCP bootstrap and tool registration.
- [ ] Add request context (session id, target id, thread id).
- [ ] Support single vs multi-session concurrency model.
- [ ] Add graceful shutdown, cleanup, and signal handling.
- [ ] Add config file and environment variable loading.

## LLDB adapter
- [ ] Create debugger lifecycle management.
- [ ] Implement target creation, attach, launch, and detach flows.
- [ ] Add thread and frame selection helpers.
- [ ] Translate LLDB errors into MCP error responses.
- [ ] Add process state tracking and event polling.

## Tools: runtime control
- [ ] breakpoint.set / breakpoint.clear / breakpoint.list / breakpoint.enable / breakpoint.disable
- [ ] execution.continue / execution.pause / execution.step (into, over, out) / execution.finish
- [ ] thread.list / thread.select / thread.info
- [ ] registers.read / registers.write (support register groups)
- [ ] memory.read / memory.write / memory.search
- [ ] stack.backtrace / frame.select

## Tools: module and symbol inspection
- [ ] modules.list and module.info (segments, sections, permissions)
- [ ] symbols.resolve and symbols.search
- [ ] memory.map

## ELF analysis and unpacking
- [ ] Detect in-memory ELF headers and program headers.
- [ ] Dump memory ranges to file with permissions metadata.
- [ ] Rebuild section headers and symbol table (optional).
- [ ] Reconstruct PLT/GOT and dynamic relocations.
- [ ] Provide an unpack workflow that exports a runnable ELF.
- [ ] Add entropy and signature checks for packed regions.

## Persistence and artifacts
- [ ] Configurable output directory for dumps.
- [ ] Metadata JSON for each dump (base, size, hashes).
- [ ] Optional symbol cache for faster analysis.

## Security and safety
- [ ] Path allowlist or denylist for file writes.
- [ ] Guardrails for memory writes and patching.
- [ ] Add timeouts for long-running operations.
- [ ] Redact sensitive environment data from logs.

## Testing
- [ ] Unit tests for adapter translation logic.
- [ ] Integration tests with a small ELF sample.
=======
- [x] Confirm MCP protocol and Python library choice (FastMCP).
- [x] Decide transport default (stdio).
- [x] Define supported LLDB versions and Python runtime constraints (Python 3.10+).
- [x] Establish logging, tracing, and telemetry strategy.
- [x] Define tool naming conventions and stable error codes.

## Core server scaffolding
- [x] Implement MCP bootstrap and tool registration.
- [ ] Add request context (session id, target id, thread id).
- [ ] Support single vs multi-session concurrency model.
- [x] Add graceful shutdown, cleanup, and signal handling.
- [x] Add config file and environment variable loading.

## LLDB adapter
- [x] Create debugger lifecycle management.
- [x] Implement target creation, attach, launch, and detach flows.
- [x] Add thread and frame selection helpers.
- [x] Translate LLDB errors into MCP error responses.
- [x] Add process state tracking and event polling.

## Tools: runtime control
- [x] breakpoint.set / breakpoint.clear / breakpoint.list / breakpoint.enable / breakpoint.disable
- [x] execution.continue / execution.pause / execution.step (into, over, out) / execution.finish
- [x] thread.list / thread.select / thread.info
- [x] registers.read / registers.write (support register groups)
- [x] memory.read / memory.write / memory.search
- [x] stack.backtrace / frame.select

## Tools: module and symbol inspection
- [x] modules.list and module.info (segments, sections, permissions)
- [x] symbols.resolve and symbols.search
- [x] memory.map

## ELF analysis and unpacking
- [x] Detect in-memory ELF headers and program headers.
- [x] Dump memory ranges to file with permissions metadata.
- [ ] Rebuild section headers and symbol table (optional).
- [ ] Reconstruct PLT/GOT and dynamic relocations.
- [x] Provide an unpack workflow that exports a runnable ELF.
- [ ] Add entropy and signature checks for packed regions.

## Persistence and artifacts
- [x] Configurable output directory for dumps.
- [x] Metadata JSON for each dump (base, size, hashes).
- [ ] Optional symbol cache for faster analysis.

## Security and safety
- [x] Path allowlist or denylist for file writes.
- [x] Guardrails for memory writes and patching.
- [x] Add timeouts for long-running operations.
- [ ] Redact sensitive environment data from logs.

## Testing
- [x] Unit tests for adapter translation logic.
- [x] Integration tests with a small ELF sample.
>>>>>>> master
- [ ] Regression tests for breakpoints and stepping.
- [ ] Mock LLDB for CI.

## Docs and examples
<<<<<<< HEAD
- [ ] Usage docs and example MCP client scripts.
=======
- [x] Usage docs and example MCP client scripts.
>>>>>>> master
- [ ] Tool schema docs with request and response samples.
- [ ] Troubleshooting guide for LLDB Python binding issues.

## Packaging and CI
<<<<<<< HEAD
- [ ] Choose build backend, versioning, and release flow.
- [ ] Add linting and formatting (ruff, black).
=======
- [x] Choose build backend, versioning, and release flow.
- [x] Add linting and formatting (ruff).
>>>>>>> master
- [ ] Add CI for tests and packaging.
