# ProtonInformer Usage

ProtonInformer loads Windows PE DLLs into running Windows processes hosted by Wine or Proton.

Loading a DLL executes its code inside the selected process. Only use payloads from trusted sources and verify the selected target before passing `--yes`.

> This documentation tracks the `main` branch and may describe behavior newer
> than the latest published binary release. Check the release tag before
> applying these instructions to an installed package.

For a flag-by-flag command reference, see [CLI Reference](cli.md).

## Download

Download the Linux archive and checksum from the [latest release](https://github.com/locainin/ProtonInformer/releases/latest).

For v0.1.7:

```bash
curl -LO https://github.com/locainin/ProtonInformer/releases/download/v0.1.7/proton-informer-v0.1.7-linux-x86_64.tar.gz
curl -LO https://github.com/locainin/ProtonInformer/releases/download/v0.1.7/proton-informer-v0.1.7-linux-x86_64.tar.gz.sha256
sha256sum --check proton-informer-v0.1.7-linux-x86_64.tar.gz.sha256
tar -xzf proton-informer-v0.1.7-linux-x86_64.tar.gz
cd proton-informer-v0.1.7-linux-x86_64
```

Keep `proton-informer` beside the `helpers/` directory. The controller discovers the packaged x86 and x86_64 Windows helpers from that layout.

## Verify The Package

```bash
./proton-informer verify-install --arch x86-64
./proton-informer verify-install --arch x86
```

Use a running Wine or Proton process for a live helper version and schema probe:

```bash
./proton-informer verify-install --pid 12345
```

The displayed helper path is the current installation path on the local machine. Release binaries do not embed maintainer home directories or workspace paths.

## Find A Target

List supported Wine and Proton processes:

```bash
./proton-informer processes --wine-only
```

List discovered Steam games and Proton prefixes:

```bash
./proton-informer steam-games
```

Inspect readiness:

```bash
./proton-informer doctor
./proton-informer doctor --pid 12345
```

Use `--debug` with text output when the selected Proton runtime, Wine prefix, compatdata directory, or Steam environment matters:

```bash
./proton-informer --debug inject --app-id 311210 --process BlackOps3.exe --payload ./mod.dll --dry-run
```

For process discovery diagnostics:

```bash
./proton-informer --debug processes --wine-only
```

`--debug` also prints scan-level process rejections and optional procfs
evidence failures that are suppressed from normal text output.

## Target Identity

ProtonInformer treats Steam and Proton identity values as authoritative
evidence rather than fallback hints.

When multiple identity sources are available, their values must agree.
Conflicting Steam AppIDs or compatdata paths are rejected. If both
`WINEPREFIX` and Steam compatdata identify the target, `WINEPREFIX` must
identify the corresponding `compatdata/<appid>/pfx` prefix.

Runtime identity paths such as `WINEPREFIX`, `STEAM_COMPAT_DATA_PATH`,
`PROTONPATH`, and Steam compatibility-tool paths must be absolute Linux paths
where required. The selected Wine prefix must also exist and be a directory.
Explicit invalid identity is rejected rather than treated as missing and
replaced by another source.

After Linux target selection, the helper correlates the target to an exact
Windows process identity. Failures inspecting unrelated Windows processes do
not relax the selected target's identity requirements.

## Inspect And Plan

Inspect a Windows PE DLL from its binary headers:

```bash
./proton-informer inspect ./mod.dll
```

Check target compatibility without loading:

```bash
./proton-informer plan --pid 12345 --payload ./mod.dll
```

`plan` uses the default staged-copy mode unless `--original-payload-path` is passed.

Create the exact helper request without executing it:

```bash
./proton-informer inject --app-id 311210 --payload ./mod.dll --dry-run
./proton-informer load --pid 12345 --payload ./mod.dll --dry-run
```

## Wine Path Mapping

Host payload paths must resolve through one unambiguous Wine drive mapping.
ProtonInformer rejects ambiguous or broken drive mappings rather than choosing
one arbitrarily.

Windows paths must use the supported absolute drive-rooted forms. Drive-
relative, root-relative, UNC, and Win32-invalid filename components are
rejected when they cannot be represented safely by the current loader path.

## Load A DLL

Select the unique running game for one Steam AppID:

```bash
./proton-informer inject --app-id 311210 --payload ./mod.dll --yes
```

Disambiguate multiple game processes:

```bash
./proton-informer inject \
  --app-id 311210 \
  --process BlackOps3.exe \
  --payload ./mod.dll \
  --yes
```

Wait for a named final process when a launcher starts before the game:

```bash
./proton-informer inject \
  --app-id 311210 \
  --process BlackOps3.exe \
  --wait-for 30s \
  --payload ./mod.dll \
  --yes
```

`--wait-for` requires both `--app-id` and `--process`. It takes a bounded duration
and never guesses which launcher child should receive the DLL.

Select an exact Linux PID:

```bash
./proton-informer inject --pid 12345 --payload ./mod.dll --yes
```

Some DLLs expect their own path to be inside the game directory. For those, keep
the original validated payload path instead of loading a private staged copy.
This mode is less isolated: dependency and path behavior stays tied to the live
game directory. The default staged-copy mode is safer when the DLL does not need
game-directory-relative lookup.

```bash
./proton-informer inject \
  --pid 12345 \
  --payload "/path/to/game/mod.dll" \
  --original-payload-path \
  --yes
```

`--yes` is required for a real load. `--dry-run` and `--yes` cannot be used together.

A real load can also end with an indeterminate result. This means the helper
cannot prove whether the target was modified, for example after a remote
thread timeout or inconclusive post-load module verification.

Do not automatically retry an indeterminate load. `LoadLibraryW` may already
have executed inside the target process.

## Inspect Loaded Modules

```bash
./proton-informer modules --pid 12345
./proton-informer modules --app-id 311210 --process BlackOps3.exe
```

Module output shows the Windows PID, process identity, module basename, and loaded Windows path.

Load output includes a module diff with before/after counts and newly observed module paths. If the DLL was already present, the result reports `Already loaded` and `added: none`.

Load success is verified against the expected full Windows module path. A DLL
with the same basename loaded from another directory does not count as the
requested payload and is treated as a conflict.

## Manage Run State

List owner-controlled request directories:

```bash
./proton-informer runs
./proton-informer runs --prefix "$WINEPREFIX"
```

Remove all validated run directories:

```bash
./proton-informer cleanup
./proton-informer cleanup --prefix "$WINEPREFIX"
```

Remove only older entries:

```bash
./proton-informer cleanup --older-than 7d
./proton-informer cleanup --prefix "$WINEPREFIX" --older-than 7d
```

Accepted age units are seconds (`s`), minutes (`m`), hours (`h`), and days (`d`).

## Startup Override Planning

Plan a Wine DLL override without modifying files:

```bash
./proton-informer override-plan \
  --app-id 311210 \
  --payload ./mod.dll \
  --dll-name mod
```

An explicit existing Wine prefix can be used instead of an AppID:

```bash
./proton-informer override-plan \
  --prefix "$HOME/Games/example-prefix" \
  --payload ./mod.dll \
  --dll-name mod
```

## JSON Output

Place `--json` before the command:

```bash
./proton-informer --json processes --wine-only
./proton-informer --json modules --pid 12345
./proton-informer --json inject --pid 12345 --payload ./mod.dll --dry-run
```

Structured load failures include stable error kinds. `windows_error` is
included only when the helper has an authoritative Windows API error code.
The standard remote-thread loader cannot retrieve the target thread's
`GetLastError`, and its 32-bit thread status is not a full pointer-sized
`HMODULE`.

Indeterminate load outcomes are distinct from confirmed rejections so
automation can avoid unsafe retries.

Text output uses terminal color for success, warning, and failure labels when color is supported. Set `NO_COLOR=1` to disable ANSI color.
