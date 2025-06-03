# Diablo II Legacy Timer Restorer

Restores pre-1.06 time caching logic to `Fog.dll` for improved compatibility in emulated environments.

## Overview

This Python script restores the original `CRITICAL_SECTION`-based time caching mechanism used in Diablo II versions prior to 1.06. Starting with 1.06, Blizzard transitioned to atomic `cmpxchg`-based logic, which breaks compatibility with virtual machines and emulators such as **DOSBox Pure**.

This patch removes those atomic operations and reinstates thread-safe logic using `InitializeCriticalSection`, reintroducing legacy behavior for improved determinism and compatibility.

## Features

- ✅ Automatically detects Diablo II version from `Fog.dll` timestamp
- ✅ Applies patch only to affected versions (1.06 and later)
- ✅ Reconstructs legacy time logic using Keystone/Capstone
- ✅ Writes in-place or to a user-specified output directory
- ✅ Creates `.bak` backup for safety when patching in place
- ✅ Fully restores:
  - Legacy initialize time function setup logic
  - Legacy calculate time function logic
  - Global time/tick memory structure

## Requirements

- Python 3.9+
- [`lief`](https://github.com/lief-project/LIEF)
- [`capstone`](https://www.capstone-engine.org/)
- [`keystone-engine`](https://www.keystone-engine.org/)
- [`colorama`](https://pypi.org/project/colorama/)

Install dependencies:

```bash
pip install lief capstone keystone-engine colorama
```

## Usage

```bash
python LegacyTimerRestorer.py
```

To write patched DLLs to a different directory (preserves originals):

```bash
python LegacyTimerRestorer.py --output-dir patched/
```

By default, the script searches for `Fog.dll` in the current directory. When `--output-dir` is provided, it recursively searches all subdirectories (excluding the output directory).

## Prepatched DLLs

A ZIP archive is available containing `Fog.dll` files from [D2VersionChanger](https://github.com/ChaosMarc/D2VersionChanger), prepatched with the legacy timer logic.

You can download the prepatched DLLs from the [Releases section](../../releases).

## Compatibility

This patch is intended for Diablo II versions **1.06 and above**. It will automatically skip versions where patching is unnecessary (i.e., 1.05b and earlier).

