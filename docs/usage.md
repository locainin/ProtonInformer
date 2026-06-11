# ProtonInformer Usage

ProtonInformer loads Windows PE DLLs into running Windows processes hosted by Wine or Proton.

Loading a DLL executes its code inside the selected process. Only use payloads from trusted sources and verify the selected target before passing `--yes`.

For a flag-by-flag command reference, see [CLI Reference](cli.md).

## Download

Download the Linux archive and checksum from the [latest release](https://github.com/locainin/ProtonInformer/releases/latest).

For v0.1.5:

```bash
curl -LO https://github.com/locainin/ProtonInformer/releases/download/v0.1.5/proton-informer-v0.1.5-linux-x86_64.tar.gz
curl -LO https://github.com/locainin/ProtonInformer/releases/download/v0.1.5/proton-informer-v0.1.5-linux-x86_64.tar.gz.sha256
sha256sum --check proton-informer-v0.1.5-linux-x86_64.tar.gz.sha256
tar -xzf proton-informer-v0.1.5-linux-x86_64.tar.gz
cd proton-informer-v0.1.5-linux-x86_64
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

## Inspect And Plan

Inspect a payload from its binary headers:

```bash
./proton-informer inspect ./mod.dll
```

Check target compatibility without loading:

```bash
./proton-informer plan --pid 12345 --payload ./mod.dll
```

Create the exact helper request without executing it:

```bash
./proton-informer inject --app-id 311210 --payload ./mod.dll --dry-run
./proton-informer load --pid 12345 --payload ./mod.dll --dry-run
```

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

## Inspect Loaded Modules

```bash
./proton-informer modules --pid 12345
./proton-informer modules --app-id 311210 --process BlackOps3.exe
```

Module output shows the Windows PID, process identity, module basename, and loaded Windows path.

Load output includes a module diff with before/after counts and newly observed module paths. If the DLL was already present, the result reports `Already loaded` and `added: none`.

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

Structured load failures include stable error kinds and target-side Windows error codes when Wine exposes them.

Text output uses terminal color for success, warning, and failure labels when color is supported. Set `NO_COLOR=1` to disable ANSI color.
