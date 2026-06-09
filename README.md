# ProtonInformer

ProtonInformer is a Linux-native CLI for loading Windows PE DLLs into Wine and Proton processes.

It is built for Linux users who need a clean Proton/Wine-aware loader instead of running random Windows injector tools by hand inside a prefix. The Linux controller finds and validates the target, checks the payload, stages the request, launches the matching Windows helper inside the selected runtime, and confirms that the expected module was loaded.

The design is inspired by System Informer-style module workflows and the classic `LoadLibrary` injector model used by projects such as [`kubo/injector`](https://github.com/kubo/injector), but ProtonInformer is built specifically around Linux, Wine, Proton, Steam prefixes, and reproducible helper packaging.

## What it does

ProtonInformer provides:

- Linux-native target discovery
- Wine and Proton process classification
- Steam AppID based process selection
- explicit Linux PID based process selection
- PE payload inspection from binary headers
- architecture matching before load
- Wine prefix and drive mapping awareness
- private request staging
- Windows helper execution inside the target prefix
- exact Windows process identity checks
- `LoadLibraryW` based DLL loading
- post-load module verification
- JSON output for scripts and frontends

The main program is the Linux binary:

```text
proton-informer
```

The Windows `.exe` files are internal helpers used by Wine or Proton:

```text
proton-informer-win-helper.exe      64-bit Windows helper
proton-informer-win32-helper.exe    32-bit Windows helper
```

Users normally run `proton-informer`, not the helper executables directly.

Download, verification, and command examples are available in the [usage guide](docs/usage.md).

## How it works

The Linux controller performs the orchestration:

1. Inspect the payload from binary headers.
2. Identify the Wine or Proton target.
3. Check ownership, architecture, prefix, and process evidence.
4. Stage the payload and request in private run state.
5. Launch the matching Windows helper inside the selected runtime.
6. Resolve the exact Windows process.
7. Load the DLL with `LoadLibraryW`.
8. Enumerate modules afterward.
9. Report success only when the expected module path is present.

This keeps the Linux-side UX clean while keeping the actual Windows loading step inside the correct Wine or Proton environment.
