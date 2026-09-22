# FFI ownership regression audit

Linux/GNU-linker diagnostic executable. Includes the selected **actual Rust FFI
source** and either links the original Go C archive or substitutes a small C
backend for repeated ownership/error-path checks. No changes to proving logic.

The Rust global allocator counts requested live bytes. At each API return the
audit subtracts the exact capacities of Rust strings returned to the test caller;
those strings remain valid caller-owned results. The residual must equal all
input CString bytes in the old implementation, or zero in the fixed one.

Linker wrappers register every C allocation returned by the five Go exports,
including the proof container and its two child strings. A `free` wrapper counts
their actual releases. It uses a fixed-size table and never tracks Go heap
objects or allocator-reserved space as FFI leaks. Byte counts include terminating
NULs and exclude allocator overhead. The old implementation serves as a positive
control: it must reproduce the exact predicted leaks, not merely show high RSS.

Build with absolute paths, using the same Rust toolchain for both arms:

```sh
FFI_AUDIT_SOURCE=/absolute/path/to/ffi/src/lib.rs \
FFI_AUDIT_MOCK=1 cargo build --offline --release
./target/release/ffi-ownership-audit fixed mock 1000 > mock-results.jsonl
```

For the positive control, select an unchanged baseline source file and pass
`old` instead of `fixed`. Save separate executables before switching the source.
Mock mode exercises both generation APIs with success/error returns, successful
and failed verification, initialization, and successful/failed export. Fixed mode
also checks cleanup when a container, child string, or returned string is null.

For real proving, unset `FFI_AUDIT_MOCK` and set `FFI_AUDIT_ARCHIVE` to the
`libg16verifier.a` built by the production `ffi/build.rs`, with the online Go
toolchain. The declarations in this audit match its generated C header.

```sh
FFI_AUDIT_SOURCE=/absolute/path/to/ffi/src/lib.rs \
FFI_AUDIT_ARCHIVE=/absolute/path/to/libg16verifier.a cargo build --offline --release
./target/release/ffi-ownership-audit fixed real /absolute/private/artifacts
```

Real mode expects the previously exported `ffi/{bridge,deposit,withdrawal}-00/`
input triples and `keystore/{,deposit_append,withdrawal_claim}/` setup files.
It loads each setup once, generates and independently verifies a real proof
through each generation entry point, tests recovered generation errors, and
exercises verification/export errors. It performs no network RPC or transaction.
Run with private stdout/stderr files: the unchanged Go backend prints proof data.
Use the external replay monitor for RSS/time guards, and only print JSON lines
whose `event` is `ownership`, `proof_verified`, `start`, or `finished`.

This audit proves ownership balance at the selected FFI boundaries, not the
absence of all possible leaks in Go caches or the full RPC/proving process.
Zero leaked requested bytes does not imply that glibc immediately returns its
free pages to the kernel; allocator reclamation is a separate concern.
