# ProtonInformer Windows Helper

`proton-informer-win-helper.exe` is the small Windows-side worker that the
Linux controller runs inside the same Wine or Proton runtime as the selected
target process. It is not intended to be a standalone user interface. The
controller validates the Linux-side inputs, writes one bounded JSON request, and
starts this helper with the exact runtime and request path.

The helper exists so Windows process enumeration, module snapshots, payload
locking, and `LoadLibraryW` execution happen inside the target prefix instead of
being guessed from Linux.

## Commands

The executable accepts only one command at a time:

```text
proton-informer-win-helper.exe --request-json <windows-path>
proton-informer-win-helper.exe --self-test-json
proton-informer-win-helper.exe --version-json
proton-informer-win-helper.exe --help
```

Unknown commands, non-Unicode command names, missing arguments, and extra
arguments are rejected before any request handling.

## Protocol Flow

`--request-json` reads a single request file with a hard size cap. Parse errors
and validation errors are returned as protocol JSON when possible so the
controller can keep request correlation.

Valid requests dispatch to one of three operations:

- `query_processes`: enumerate visible Windows processes and return process
  name, Windows PID, architecture, creation time, and executable path when
  readable. Per-process identity read failures remain in the result as
  structured rejections
- `query_modules`: resolve one exact target and return its loaded module list
- `load_library`: validate, load, and verify one DLL in one resolved target

Host-native helper builds intentionally expose only `version` and `self-test`
capabilities. Process queries, module queries, payload locking, and loading are
Windows-only operations.

## Load Operation

The load path is deliberately narrow:

1. Reject non-absolute or parent-relative Windows payload paths.
2. Open the payload through Windows APIs and keep a read lock that denies write
   and delete sharing.
3. Canonicalize the payload path from the open handle.
4. Recheck the controller-provided size and SHA-256 with bounded memory.
5. Read only the PE headers needed to prove the file is a DLL for the target
   architecture.
6. Resolve the target again and enumerate its modules before loading.
7. Treat an already loaded exact module path as an idempotent success.
8. Reject a same-basename module loaded from a different full path. File
   contents never substitute for the requested module path.
9. Run a standard remote `LoadLibraryW` thread in the target process.
10. Resolve the target identity again, enumerate modules again, and report
    success only when the canonical payload path is present.

The helper reports module counts before and after the load, whether the request
was already loaded, and every module path that appeared after the request.

## Loader Diagnostics

The current loader uses the standard
`CreateRemoteThread(LoadLibraryW, payload_path)` pattern. That keeps the remote
mutation small, but it also means the helper cannot safely read the target
thread's `GetLastError`.

On x86, when the completed remote thread reports a zero 32-bit exit status, the
helper reports:

```text
LoadLibraryW returned a zero 32-bit thread exit status; target-side GetLastError is unavailable in standard loader mode.
```

The protocol omits `windows_error` for that case. The value is a thread exit
status, not a full pointer-sized `HMODULE`, and a zero value does not provide a
target-side `GetLastError`.

On x64, a zero low 32-bit status cannot prove that the pointer-sized
`LoadLibraryW` result was null. If the exact module is not observed, the helper
therefore reports an indeterminate outcome for every x64 low-bit value.

If the thread wait or the final module snapshot cannot prove whether the
remote load finished, the helper returns an indeterminate outcome. The
controller must not retry that request automatically.

Dependency preflight is advisory only. Import parsing can produce warnings on
successful loads, and parser failures become skipped-preflight warnings in
internal load state. Preflight never replaces the final Windows loader or module
verification result.

## Target Safety

The helper resolves target identity from the request rather than trusting one
loose process name. Exact PID requests require the expected creation time and
executable path. Name/path selectors must match the expected architecture and
executable path. Ambiguous matches fail instead of guessing.

Remote loading opens the target with only the rights needed for the standard
loader path. Remote memory that may still be used by a timed-out thread is not
freed early.

## Windows API Boundary

Raw handles, pointers, snapshots, and remote memory live under `src/winapi/`.
The rest of the helper consumes typed wrappers and protocol models. This keeps
unsafe Windows API code in one boundary and keeps request dispatch, validation,
and result shaping testable without spreading raw pointer logic through the
helper.

The helper is built with `deny(warnings)`, `deny(unsafe_op_in_unsafe_fn)`, and
strict Clippy linting. Keep memory use bounded for request reads, hashing, PE
parsing, and helper output.
