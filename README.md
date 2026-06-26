# Decompiler

Decompiler is a native macOS application that opens executable files, disassembles executable code with [Capstone](https://www.capstone-engine.org/), and renders C-like pseudocode beside the raw assembly.

The app is intended as a lightweight reverse-engineering viewer: it helps inspect executable entry code quickly, compare disassembly with a readable pseudocode approximation, and switch between several pseudocode presentations.

## Features

- Native Cocoa macOS interface.
- Side-by-side panes for disassembly and decompiled pseudocode.
- Capstone-backed instruction decoding.
- Executable container detection for:
  - Mach-O
  - Universal Mach-O
  - ELF
  - PE/COFF
  - Raw binary fallback
- Architecture selection for common executable targets, including x86, x86_64, ARM, ARM64, MIPS, PowerPC, and RISC-V where the container metadata provides enough information.
- Pseudocode style selector:
  - `Structured C`
  - `Compact C`
  - `Verbose IR`
  - `Control Flow`
- macOS app icon asset set.

## Requirements

- macOS with Xcode installed.
- Homebrew Capstone installed at `/opt/homebrew/opt/capstone`.

Install Capstone:

```sh
brew install capstone
```

The Xcode project currently links against the Homebrew Apple Silicon prefix:

```text
/opt/homebrew/opt/capstone/include
/opt/homebrew/opt/capstone/lib
```

If Capstone is installed somewhere else, update `HEADER_SEARCH_PATHS`, `LIBRARY_SEARCH_PATHS`, and `LD_RUNPATH_SEARCH_PATHS` in `Decompiler.xcodeproj`.

## Build

From the repository root:

```sh
xcodebuild -project Decompiler.xcodeproj -scheme Decompiler -configuration Debug build
```

Or open `Decompiler.xcodeproj` in Xcode and build the `Decompiler` scheme.

## Usage

1. Launch the app.
2. Click `Open Executable`.
3. Select a Mach-O, ELF, PE/COFF, or raw executable image.
4. Inspect the left pane for Capstone disassembly.
5. Inspect the right pane for pseudocode.
6. Use the `Pseudocode` selector to switch output style.

The metadata line shows the detected file format, architecture, entry point, and any fallback warnings.

## Pseudocode Modes

`Structured C` runs a lightweight symbolic pass over the decoded instructions. It tracks register expressions, maps ABI argument registers to `arg0` through `arg3`, renders memory operands as pointer dereferences, derives comparison-based branch conditions, and emits C-like temporaries instead of wrapping assembly text.

`Compact C` emits the same symbolic C-like logic with less address commentary.

`Verbose IR` emits a linear intermediate representation with instruction addresses, mnemonics, operands, and bytes.

`Control Flow` emphasizes labels, conditional branches, and gotos so branch structure is easier to scan.

## Current Limitations

This is a heuristic decompiler, not a full SSA/control-flow recovery system. It does not currently perform full type recovery, stack variable reconstruction, global liveness analysis, function boundary discovery, symbol recovery, structured loop reconstruction, or cross-reference analysis.

Unknown or unsupported instructions are represented as named semantic effect helpers such as `state = op_name_effect(state, ...)` so information is not silently discarded without falling back to inline assembly blocks.

Container parsing focuses on finding executable bytes and a reasonable entry/code section. For heavily packed, obfuscated, stripped, malformed, or unusual binaries, the output may require manual interpretation.

## Project Layout

```text
Decompiler/
  AppDelegate.h
  AppDelegate.m
  DecompilerEngine.h
  DecompilerEngine.m
  Assets.xcassets/
  Base.lproj/MainMenu.xib
Decompiler.xcodeproj/
README.md
```

`DecompilerEngine` owns executable parsing, Capstone setup, disassembly, and pseudocode rendering.

`AppDelegate` owns the macOS window, file picker, pseudocode selector, and two-pane text UI.

## Verification

The current project has been verified with:

```sh
xcodebuild -project Decompiler.xcodeproj -scheme Decompiler -configuration Debug build
```
