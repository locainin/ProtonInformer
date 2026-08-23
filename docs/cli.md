# ProtonInformer CLI Reference

This reference is generated from the current CLI behavior and code paths.

## Global Flags

Global flags can be placed before or after a subcommand.

```bash
./proton-informer --json <command>
./proton-informer <command> --debug
```

`--json` prints machine-readable output for command results and errors. JSON mode disables color and suppresses debug-only text.

`--debug` adds target and runtime context to text output. It is ignored in JSON output so scripts keep a stable schema.

Text output uses color only when both stdout and stderr are terminals, `TERM` is not `dumb`, and `NO_COLOR` is unset. Success states are green, warning states are yellow, and failure labels are red.

## Commands

### `cleanup`

Remove safe controller-managed run state.

```bash
./proton-informer cleanup
./proton-informer cleanup --older-than 7d
./proton-informer cleanup --prefix "$WINEPREFIX"
```

`--older-than` accepts compact durations with `s`, `m`, `h`, or `d`.

### `doctor`

Check Steam discovery, process inspection, Wine commands, helper files, and state storage.

```bash
./proton-informer doctor
./proton-informer doctor --pid 12345
```

With `--pid`, doctor also runs helper version and self-test probes inside the selected Wine or Proton runtime.

### `inspect`

Inspect a payload from binary headers.

```bash
./proton-informer inspect ./payload.dll
```

### `inject`

Find a Wine or Proton target and load one validated PE DLL.

```bash
./proton-informer inject --app-id 311210 --payload ./payload.dll --yes
./proton-informer inject --pid 12345 --payload ./payload.dll --yes
```

Useful selection and execution flags:

- `--app-id <id>` selects by Steam AppID
- `--pid <pid>` selects one exact Linux process
- `--process <name>` disambiguates AppID matches by guest executable basename
- `--wait-for <duration>` waits for the named final game process
- `--dry-run` writes request artifacts without running the helper
- `--yes` executes the validated request
- `--keep-run-files` retains bounded helper stdout and stderr
- `--original-payload-path` loads the validated source path instead of a staged private copy
- `--timeout-ms <ms>` bounds helper execution from 1 to 300000 ms

The normal staged-copy mode places the DLL under the private run directory. `--original-payload-path` is less isolated and should be used only when the DLL needs game-directory-relative dependency or path behavior.

Successful text output includes the selected Linux target, guest executable, Steam AppID, Proton runtime, Wine prefix, load result, and module diff.

```text
Loaded:
  C:\path\payload.dll

Module diff:
  before: 142
  after:  143
  added:
    + C:\path\payload.dll
```

If the module was already present, the load result reports `Already loaded` and the added list is `none`.

### `load`

Prepare or execute a helper-backed load for a known Linux PID.

```bash
./proton-informer load --pid 12345 --payload ./payload.dll --dry-run
./proton-informer load --pid 12345 --payload ./payload.dll --yes
```

`load` uses the same payload path, run-file, timeout, dry-run, and execution flags as `inject`, but does not do Steam AppID process selection.

### `modules`

List modules loaded by one exact Wine or Proton process.

```bash
./proton-informer modules --pid 12345
./proton-informer modules --app-id 311210 --process BlackOps3.exe
./proton-informer modules --pid 12345 --filter d3d --contains system32
```

`--filter` matches the module basename. `--contains` matches either the module basename or full Windows path. Empty filter values are rejected.

### `override-plan`

Plan a Wine startup DLL override without modifying files.

```bash
./proton-informer override-plan --app-id 311210 --payload ./winhttp.dll --dll-name winhttp
./proton-informer override-plan --prefix "$WINEPREFIX" --payload ./winhttp.dll --dll-name winhttp.dll
```

The plan prints the `WINEDLLOVERRIDES` launch option and warns that the payload still needs to be placed in the application DLL search path.

### `plan`

Validate a payload and target compatibility without writing helper request files.

```bash
./proton-informer plan --pid 12345 --payload ./payload.dll
./proton-informer plan --pid 12345 --payload ./payload.dll --target-arch x86-64
./proton-informer plan --pid 12345 --payload ./payload.dll --original-payload-path
```

Wine targets do not fall back to the Linux host architecture. If the guest architecture is unknown, provide `--target-arch`.

The default plan models staged-copy mode, so the source payload path does not need to be visible through the selected prefix's Wine drives. `--original-payload-path` keeps the source-path visibility requirement because the helper will load that path directly.

### `processes`

List readable Linux, Wine, and Proton processes.

```bash
./proton-informer processes
./proton-informer processes --wine-only
```

`processes --json` keeps the established top-level array shape for script
compatibility. The process row contract intentionally changes with the 0.1.6
release: `host_architecture` was removed with the out-of-scope native-loader
model, `environment_status` includes `not_inspected` for scan-only rows, and
Each row also includes the Linux process `start_time_ticks` identity field, and
`evidence_failures` can carry optional procfs-read diagnostics. JSON consumers
must update for these row-level changes; the stable top-level array does not
mean that individual fields are unchanged. Detailed scan rejections and
optional evidence-read failures are emitted only by text mode with `--debug`.

### `runs`

List safe controller-managed run state.

```bash
./proton-informer runs
./proton-informer runs --prefix "$WINEPREFIX"
```

### `steam-games`

List discovered Steam games and existing Proton prefixes.

```bash
./proton-informer steam-games
```

### `verify-install`

Verify helper permissions, checksums, versions, schemas, and architectures.

```bash
./proton-informer verify-install --arch x86
./proton-informer verify-install --arch x86-64
./proton-informer verify-install --pid 12345
```

`--arch` performs offline static helper verification. `--pid` also probes the helper inside a live Wine or Proton runtime.

If `PROTON_INFORMER_HELPER_DIR` is set, helper lookup prefers that absolute directory and verify output reports it as an environment override.

## Error Output

Text errors use a red `Error:` label when terminal color is enabled. JSON errors include a stable `kind`, `message`, and optional `windows_error`.

On 32-bit targets, a zero loader-thread status can support a rejection when
target-side `GetLastError` is unavailable. On 64-bit targets, the same low
32-bit value cannot prove a null `HMODULE`, so a missing verified module is
reported as indeterminate instead. The 32-bit message is:

```text
LoadLibraryW returned a zero 32-bit thread exit status; target-side GetLastError is unavailable in standard loader mode.
```

The reported thread status is not a full pointer-sized `HMODULE`. Timeout or
post-thread verification failures are reported as indeterminate outcomes, and
must not be retried automatically. Helper rejection errors can still include a
real target-side Windows error when the helper has one.
