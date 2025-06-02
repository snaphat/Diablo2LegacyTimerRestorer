"""
Diablo II Legacy Timer Restorer for Fog.dll (Pre-1.06 Caching Logic)

This script restores the pre-1.06 critical-section-based time caching logic
used in Fog.dll, part of the Diablo II game engine. Starting with version 1.06,
Blizzard replaced this logic with atomic operations (`cmpxchg`), which are
incompatible with some emulated or virtual environments such as DOSBox Pure.

The restoration process:
- Reintroduces thread-safe time caching using `InitializeCriticalSection`.
- Eliminates use of unsupported atomic operations (`cmpxchg`) introduced in 1.06.
- Improves compatibility with virtualized and retro PC gaming setups.

Tools Used:
- LIEF: For parsing and modifying PE (Portable Executable) binaries.
- Capstone: For disassembling x86 machine code.
- Keystone: For assembling x86 instructions into machine code.
- Colorama: For colored CLI output.
"""

import argparse
import os
import shutil
import sys
from typing import List, Optional, Tuple

import colorama
import lief
from capstone import CS_ARCH_X86, CS_MODE_32, Cs, CsInsn
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM
from colorama import Fore, Style
from keystone import KS_ARCH_X86, KS_MODE_32, Ks, KsError
from lief.PE import Binary, Section

# Initialize Colorama for colored CLI output
colorama.init(autoreset=True)

# region Known Diablo II Fog.dll Version Timestamps

VERSION_100_TIMESTAMP       = 0x392ec7d4
VERSION_101_TIMESTAMP       = 0x3957d5f7
VERSION_102_TIMESTAMP       = 0x3966576f
VERSION_103_TIMESTAMP       = 0x3986136c
VERSION_104B_TIMESTAMP      = 0x3a3b5c92
VERSION_104C_TIMESTAMP      = 0x3a3b5c92
VERSION_105_TIMESTAMP       = 0x3a720eee
VERSION_105B_TIMESTAMP      = 0x3a79c9d4
VERSION_106_TIMESTAMP       = 0x3ade4595
VERSION_106B_TIMESTAMP      = 0x3b02c8ec
VERSION_107_TIMESTAMP       = 0x3af6e1d9
VERSION_108_TIMESTAMP       = 0x3b2eb277
VERSION_109_TIMESTAMP       = 0x3b7c4e0f
VERSION_109B_TIMESTAMP      = 0x3b7c4e0f
VERSION_109D_TIMESTAMP      = 0x3c06fcd3
VERSION_100_BETA1_TIMESTAMP = 0x3f0472c7
VERSION_100_BETA2_TIMESTAMP = 0x3f24b36e
VERSION_110_TIMESTAMP       = 0x3f8a5c4f
VERSION_111_TIMESTAMP       = 0x42e6c1f0
VERSION_111B_TIMESTAMP      = 0x43028af2
VERSION_112A_TIMESTAMP      = 0x483cb768
VERSION_113_TIMESTAMP       = 0x4b95c0aa
VERSION_113C_TIMESTAMP      = 0x4b95c0aa
VERSION_113D_TIMESTAMP      = 0x4e9de32b

FOG_DLL_VERSION_BY_TIMESTAMP  = {
    VERSION_100_TIMESTAMP:       "1.00",
    VERSION_101_TIMESTAMP:       "1.01",
    VERSION_102_TIMESTAMP:       "1.02",
    VERSION_103_TIMESTAMP:       "1.03",
    VERSION_104B_TIMESTAMP:      "1.04b | 1.04c",
    VERSION_104C_TIMESTAMP:      "1.04b | 1.04c",
    VERSION_105_TIMESTAMP:       "1.05",
    VERSION_105B_TIMESTAMP:      "1.05b",
    VERSION_106_TIMESTAMP:       "1.06",
    VERSION_106B_TIMESTAMP:      "1.06b",
    VERSION_107_TIMESTAMP:       "1.07",
    VERSION_108_TIMESTAMP:       "1.08",
    VERSION_109_TIMESTAMP:       "1.09 | 1.09b",
    VERSION_109B_TIMESTAMP:      "1.09 | 1.09b",
    VERSION_109D_TIMESTAMP:      "1.09d",
    VERSION_100_BETA1_TIMESTAMP: "1.00 Beta 1",
    VERSION_100_BETA2_TIMESTAMP: "1.00 Beta 2",
    VERSION_110_TIMESTAMP:       "1.10",
    VERSION_111_TIMESTAMP:       "1.11",
    VERSION_111B_TIMESTAMP:      "1.11b",
    VERSION_112A_TIMESTAMP:      "1.12a",
    VERSION_113_TIMESTAMP:       "1.13 | 1.13c",
    VERSION_113C_TIMESTAMP:      "1.13 | 1.13c",
    VERSION_113D_TIMESTAMP:      "1.13d",
}

#endregion

# region Utility Functions


def print_pretty(label: str, value: str, label_color: str, value_color: str, align_width: int, indent:Optional[int]=4):
    """
    Prints an aligned and colorized label–value pair to the console.

    Args:
        label (str): The label text to display.
        value (str): The value text associated with the label.
        label_color (str): ANSI color code for the label (e.g., colorama.Fore.*).
        value_color (str): ANSI color code for the value (e.g., colorama.Fore.*).
        align_width (int): Number of characters to reserve for the label alignment.
        indent (int, optional): Number of spaces to indent the line. Defaults to 4.

    Returns:
        None
    """
    indent_str = " " * indent
    formatted_label = f"{label:<{align_width}}"
    print(f"{indent_str}{label_color}{formatted_label}{Style.RESET_ALL}: " + f"{value_color}{value}{Style.RESET_ALL}")


def resolve_imported_symbol(binary: Binary, symbol_name: str) -> int:
    """
    Resolves the virtual address (VA) of an imported function by name.

    Args:
        binary (lief.PE.Binary): The LIEF PE binary object under analysis.
        symbol_name (str): The name of the imported function to resolve.

    Returns:
        int: The resolved virtual address (VA) of the imported function.

    Raises:
        RuntimeError: If the function name is not found in the import table.
    """
    base = binary.optional_header.imagebase
    print_pretty("Resolving imported symbol", symbol_name, Fore.CYAN, Style.BRIGHT + Fore.WHITE, 30)

    for entry in binary.imports:
        for function in entry.entries:
            if function.name and function.name.lower() == symbol_name.lower():
                return base + function.iat_address

    raise RuntimeError(f"Imported symbol '{symbol_name}' not found.")


def resolve_exported_symbol(binary: Binary, ordinal: int) -> int:
    """
    Resolves the virtual address (VA) of an exported function by ordinal.

    Args:
        binary (lief.PE.Binary): The LIEF PE binary object under analysis.
        ordinal (int): The export ordinal to resolve.

    Returns:
        int: The resolved virtual address (VA) of the exported function.

    Raises:
        RuntimeError: If the ordinal is not found in the export table.
    """
    base = binary.optional_header.imagebase
    print_pretty("Resolving exported symbol", str(ordinal), Fore.CYAN, Style.BRIGHT + Fore.WHITE, 30)

    export_table = binary.get_export()
    ordinal_base = export_table.ordinal_base
    ordinal_index = ordinal - ordinal_base

    if ordinal_index < 0 or ordinal_index >= len(export_table.entries):
        raise RuntimeError(f"Ordinal {ordinal} not found in export table.")

    rva = export_table.entries[ordinal_index].address
    return base + rva


def disassemble_function(virtual_address: int, binary: Binary, code_section: Section) -> List[CsInsn]:
    """
    Disassembles a sequence of bytes from the specified code section using Capstone, starting at the given virtual
    address.

    Args:
        virtual_address (int): The virtual address (VA) where disassembly should begin.
        binary (lief.PE.Binary): The LIEF PE binary object.
        code_section (lief.PE.Section): The `.text` (code) section from which to read bytes.

    Returns:
        list[capstone.CsInsn]: A list of Capstone instruction objects representing
        the disassembled function code.

    Raises:
        ValueError: If the provided `virtual_address` falls outside the boundaries
        of the specified code section.
    """
    base = binary.optional_header.imagebase
    print_pretty("Disassembling function at", f"0x{virtual_address:08X}", Fore.MAGENTA, Style.BRIGHT + Fore.WHITE, 30)

    section_bytes = bytes(code_section.content)
    section_rva = code_section.virtual_address
    # Calculate the offset within the section's raw content bytes
    offset = virtual_address - base - section_rva
    if offset < 0 or offset >= len(section_bytes):
        raise ValueError(
            f"Virtual address 0x{virtual_address:08X} is outside the code section boundaries.")

    # Disassemble from the calculated offset to the end of the section
    function_bytes = section_bytes[offset:]
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    # Enable detailed instruction information (operands, groups) for better analysis
    disassembler.detail = True
    return list(disassembler.disasm(function_bytes, virtual_address))


def apply_patch(virtual_address: int, asm_source, assembler, binary: Binary, code_section: Section) -> None:
    """
    Assembles the provided x86 assembly source code into machine bytes using Keystone, and then injects these bytes into
    the target binary's `.text` section at the specified virtual address.

    This function is central to modifying the binary, replacing existing code with the restored pre-1.06 time caching
    logic.

    Args:
        virtual_address (int): The virtual address (VA) where the patch bytes should be written.
        asm_source (str): A multi-line string containing the x86 assembly code to be assembled.
        assembler (keystone.Ks): An initialized Keystone assembler instance.
        binary (lief.PE.Binary): The LIEF binary object to be patched.
        code_section (lief.PE.Section): The `.text` (code) section of the binary.

    Raises:
        ValueError: If the assembled patch would extend beyond the boundaries
                    of the `code_section`.
    """
    base = binary.optional_header.imagebase
    print_pretty("Applying patch at", f"0x{virtual_address:08X}", Fore.YELLOW, Style.BRIGHT + Fore.WHITE, 30)
    # Assemble the provided assembly source into machine code bytes
    try:
        patch_bytes = assembler.asm(asm_source, virtual_address)[0]
    except KsError as e:
        raise RuntimeError(f"Keystone assembly failed: {e}")

    print_pretty("Patch size", f"{len(patch_bytes)} bytes", Fore.YELLOW, Style.BRIGHT + Fore.WHITE, 30)

    # Calculate the offset within the code section's content array
    offset = virtual_address - base - code_section.virtual_address

    # Perform bounds checking to ensure the patch fits within the section
    if offset < 0 or offset + len(patch_bytes) > len(code_section.content):
        raise ValueError(
            f"Patch at 0x{virtual_address:08X} (size {len(patch_bytes)} bytes) goes out of bounds of the code section.")

    # Update the content of the LIEF section object
    updated_content = list(code_section.content)
    updated_content[offset:offset + len(patch_bytes)] = patch_bytes
    code_section.content = updated_content  # Assign the modified content back

# endregion

# region Patch Assembly Generation


def init_time_asm(
        cs: int, init_cs_fn: int, crt_time_fn: int, cached_time: int, get_tick_fn: int, cached_tick: int) -> str:
    """
    Returns the assembly string for initializing the legacy time caching system in Fog.dll.

    This code replaces the logic at a subroutine called by ordinal 10017/10019. It initializes the critical section,
    calls the internal time function to compute the initial time value, and stores both the time and the current tick
    count into the appropriate memory addresses for use by the main time retrieval logic.

    Parameters:
        cs (int):          address of the CRITICAL_SECTION object.
        init_cs_fn (int):  Address of InitializeCriticalSection.
        crt_time_fn (int): Address of the internal time calculation function.
        cached_time (int): Address to store the initial time value.
        get_tick_fn (int): Address of GetTickCount (or equivalent).
        cached_tick (int): Address to store the initial tick value.

    Returns:
        str: Assembly code as a string.
    """
    return f"""
        push {cs}                          # Push address of Critical Section structure
        call dword ptr [{init_cs_fn}]      # InitializeCriticalSection
        push 0                             # Argument for internal time func (usually 0)
        call {crt_time_fn}                 # Call internal time calculation function
        add esp, 4                         # Clean up stack after call
        mov dword ptr [{cached_time}], eax # Store initial calculated time value
        call dword ptr [{get_tick_fn}]     # Get current tick count
        mov dword ptr [{cached_tick}], eax # Store initial cached tick count
        ret                                # Return
        """


def calc_time_asm(
        get_tick_fn: int, cached_tick: int, cs: int, enter_cs_fn: int, crt_time_fn: int, cached_time: int,
        leave_cs_fn: int) -> str:
    """
    Returns the assembly string that implements the restored legacy time retrieval function for Fog.dll, replacing the
    logic at ordinal 10036/10055.

    This function reconstructs the original critical-section-protected logic for time caching and computation using
    byte-for-byte opcode compatibility, including `.byte` directives to override Keystone's default encoding when
    necessary.

    Parameters:
        get_tick_fn (int): Address of GetTickCount (or equivalent).
        cached_tick (int): Address of the last cached tick value.
        cs (int):          Address of the critical section struct.
        enter_cs_fn (int): Address of EnterCriticalSection.
        crt_time_fn (int): Address of the internal time calculation function.
        cached_time (int): Address of the cached time value.
        leave_cs_fn (int): Address of LeaveCriticalSection.

    Returns:
        str: Assembly code as a string.
    """
    return f"""
        push esi                             # Save ESI register
        call dword ptr [{get_tick_fn}]       # Call GetTickCount to get current tick
        mov edx, dword ptr [{cached_tick}]   # Load last cached tick count into EDX
        .byte 0x8B, 0xF0                     # mov esi, eax (EAX holds current tick count from GetTickCount)
        .byte 0x2B, 0xC2                     # sub eax, edx (EAX = current_tick - last_cached_tick)
        cmp eax, 0x7FFFFFFF                  # Compare difference with 0x7FFFFFFF (large positive number)
        jbe skip                             # If difference is less than or equal, skip update

        # --- Time update logic (entered if time difference is significant) ---
        push {cs}                            # Push address of Critical Section structure
        call dword ptr [{enter_cs_fn}]       # EnterCriticalSection (synchronize access)
        push 0                               # Push 0 (argument for crt time function)
        call {crt_time_fn}                   # Call internal time calculation function
        add esp, 4                           # Clean up stack after call (for pushed 0)
        mov dword ptr [{cached_time}], eax   # Store new calculated time value
        mov dword ptr [{cached_tick}], esi   # Update last cached tick count with current tick from ESI
        push {cs}                            # Push address of Critical Section structure
        call dword ptr [{leave_cs_fn}]       # LeaveCriticalSection
    skip:
        # --- Time calculation for return value ---
        mov eax, dword ptr [{cached_tick}]   # Load last cached tick count into EAX
        mov ecx, dword ptr [{cached_time}]   # Load cached time value into ECX
        .byte 0x2B, 0xF0                     # sub esi, eax (ESI holds current tick, EAX last tick. ESI = current_tick - last_tick)
        mov eax, 0x10624DD3                  # Magic number for time scaling (specific to D2's timing algorithm)
        mul esi                              # Multiply EAX by ESI (signed multiplication)
        .byte 0x8B, 0xC2                     # mov eax, edx (EDX holds the high part of the mul result, which is the scaled tick difference)
        pop esi                              # Restore ESI register
        shr eax, 6                           # Shift right by 6 (divide by 64) for further scaling
        .byte 0x03, 0xC1                     # add eax, ecx (Add scaled tick difference to cached time value)
        ret                                  # Return with calculated time in EAX
    """
# endregion

# region: Symbol Locator Functions


def locate_time_initializer(init_game_ord: int, binary: Binary, code_section) -> int:
    """
    Locates the internal time initialization routine invoked by the game's global initializer.

    This function disassembles the instructions starting at the exported entry point and searches for the pattern:
        call <imm>       # call to internal initializer
        lea reg, [esp+X] # frame or return address setup

    The target of the `call` is returned as the internal time initializer. This pattern is used to identify the true
    implementation address within a larger global setup function.

    Args:
        init_game_ord (int): Virtual address of the exported global initialization function.
        binary (lief.PE.Binary): Parsed LIEF PE binary object.
        code_section (lief.PE.Section): The `.text` section containing executable code.

    Returns:
        int: Virtual address of the internal time initializer.

    Raises:
        RuntimeError: If the expected `call` followed by `lea` pattern is not found.
    """

    print(Fore.GREEN + "\n  Locating internal time initializer function...")
    insts = disassemble_function(init_game_ord, binary, code_section)

    for idx, instr in enumerate(insts):
        if instr.mnemonic == "lea" and idx > 0:
            prev = insts[idx - 1]
            if prev.mnemonic == "call" and prev.operands[0].type == X86_OP_IMM:
                return prev.operands[0].value.imm

    raise RuntimeError("Failed to locate internal time initializer: expected call + lea pattern not found.")


def locate_critical_section_struct(init_time_fn: int, init_cs_fn: int, binary: Binary, code_section: Section) -> int:
    """
    Identifies the address of the global CRITICAL_SECTION used by Fog.dll's time system by analyzing its internal time
    initialization function.

    The matched instruction pattern corresponds to a call that initializes a CRITICAL_SECTION:
        push <imm>                        # address of CRITICAL_SECTION object
        call [InitializeCriticalSection] # indirect call via IAT

    This function disassembles the instructions at the specified initializer function and searches for this `push` +
    `call` sequence. If the call target matches the IAT address of InitializeCriticalSection, the pushed immediate is
    returned as the address of the CRITICAL_SECTION.

    Args:
        init_time_fn (int): Virtual address of the internal time initialization function.
        init_cs_fn (int): IAT address of InitializeCriticalSection.
        binary (lief.PE.Binary): Parsed PE binary object.
        code_section (lief.PE.Section): `.text` section of the binary.

    Returns:
        int: Virtual address of the CRITICAL_SECTION structure.

    Raises:
        RuntimeError: If the expected pattern is not found.
    """
    insts = disassemble_function(init_time_fn, binary, code_section)

    for i in range(len(insts) - 1):
        push_instr = insts[i]
        call_instr = insts[i + 1]

        if push_instr.mnemonic == "push" and call_instr.mnemonic == "call":
            push_ops = push_instr.operands
            call_ops = call_instr.operands
            if (push_ops and push_ops[0].type == X86_OP_IMM and
                    call_ops and call_ops[0].type == X86_OP_MEM and call_ops[0].value.mem.disp == init_cs_fn):
                return push_ops[0].value.imm

    raise RuntimeError("Failed to locate critical section address near call to InitializeCriticalSection.")


def locate_crt_time_and_cache_region(
        calc_time_ord: int, get_tick_fn: int, binary: Binary, code_section: Section) -> Tuple[int, int]:
    """
    Identifies addresses used by Fog.dll's internal time computation logic and its associated shared memory region by
    analyzing the exported time calculation routine.

    The exported ordinal (e.g., 10036 or 10055) typically performs the following:
      1. Calls an internal time computation function with a dummy parameter.
      2. Invokes GetTickCount via IAT.
      3. Stores the results (time and tick count) in a shared 8-byte global memory region.

    This routine identifies two patterns:
    - Pattern 1: Locates the internal time function.
        push 0                  # push dummy/default argument
        call <imm>              # call to internal time() logic (e.g., msvcrt.time)

    - Pattern 2: Locates the base of the shared 8-byte memory region.
        mov eax, [GetTickCount] # load tick count from IAT
        ...
        mov [addr], eax         # store into global region (tick or time value)
        ...
        # Layout:
        #   [addr + 0x0] = cached time (DWORD)
        #   [addr + 0x4] = cached tick count (DWORD)

    Args:
        calc_time_ord (int): Virtual address of the exported wrapper function.
        get_tick_fn (int): IAT address of GetTickCount.
        binary (lief.PE.Binary): Parsed PE binary object.
        code_section (lief.PE.Section): `.text` section of the binary.

    Returns:
        tuple[int, int]:
            - Virtual address of the internal time function.
            - Base address of the 8-byte shared memory region.

    Raises:
        RuntimeError: If the required instruction patterns are not found.
    """
    print(Fore.GREEN + "\n  Extracting CRT time() function and cache region...")
    insts = disassemble_function(calc_time_ord, binary, code_section)
    crt_time_fn = None
    cache_region = None

    for idx, inst in enumerate(insts):
        # Look for `push 0` followed by `call <imm>` to locate the internal function
        if crt_time_fn is None and inst.mnemonic == "push" and inst.op_str == "0":
            if idx + 1 < len(insts):
                next_instr = insts[idx + 1]
                if next_instr.mnemonic == "call":
                    crt_time_fn = next_instr.operands[0].value.imm

        # Look for `mov reg, [GetTickCount@IAT]`, then `mov [addr], imm` — the address is the shared 8-byte region
        if cache_region is None and inst.mnemonic == "mov" and len(inst.operands) > 1:
            if inst.operands[1].type == X86_OP_MEM and inst.operands[1].mem.disp == get_tick_fn:
                if idx + 2 < len(insts):
                    next_instr = insts[idx + 2]
                    ops = next_instr.operands
                    if next_instr.mnemonic == "mov" and len(ops) > 1 and ops[1].type == X86_OP_IMM:
                        cache_region = next_instr.operands[1].value.imm

    if crt_time_fn is None or cache_region is None:
        raise RuntimeError("Failed to locate time function and shared memory region.")

    return crt_time_fn, cache_region

# endregion

# region: Patch Application Logic


def patch_fog_dll(file_path: str, output_dir: Optional[str] = None) -> bool:
    """
    Applies a patch to a Diablo II Fog.dll binary that restores the original time caching logic used in pre-1.06
    versions of the game.

    This involves:
    - Identifying exported and imported symbol addresses
    - Locating internal routines and data structures
    - Generating and injecting x86 assembly into the binary
    - Creating or restoring backups to ensure safe patching

    Args:
        file_path (str): Full path to the Fog.dll binary to patch.
        output_dir (Optional[str]): If provided, writes the patched binary to a parallel path rooted at output_dir.
                                    Otherwise, modifies in-place.

    Returns:
        bool: True if the patch was applied successfully or unnecessary due to version;
              False if an error occurred and patching failed.
    """
    print(Fore.WHITE + f"\n--- Processing: {file_path} ---")

    backup_path = file_path + ".bak"  # Path to the definitive original backup

    try:
        # Load the binary using LIEF and ensure it's valid
        print(Fore.GREEN + "  Loading binary...")
        binary = lief.parse(file_path)
        if binary is None:
            raise RuntimeError("Failed to parse the binary. Please ensure it's a valid PE file.")

        # Detect game version using the PE timestamp
        timestamp = binary.header.time_date_stamps
        current_version_name = FOG_DLL_VERSION_BY_TIMESTAMP.get(timestamp, "Unknown")
        print_pretty("Fog.dll Version", current_version_name, Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)
        print_pretty("Timestamp", f"0x{timestamp:08X}", Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)

        # Abort if patching is not required (version predates 1.06)
        if timestamp < VERSION_106_TIMESTAMP:
            print_pretty("Info", "Fog.dll is from a version earlier than 1.06. Patching is not necessary.",
                         Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)
            return True

        # Resolve output path
        if output_dir:
            out_path = os.path.join(output_dir, os.path.relpath(file_path, start='.'))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            print(Fore.CYAN + f"Writing patched to: {out_path}")
            target_path = out_path
        else:
            target_path = file_path

        # Backup: if a .bak file exists, restore it to patch a clean copy;
        # otherwise create one if patching in-place
        if os.path.exists(backup_path):
            print(Fore.YELLOW + f"  Found backup at '{backup_path}'. Restoring it to '{file_path}' before patching.")
            if not output_dir:
                shutil.copy2(backup_path, file_path)
        elif not output_dir:
            shutil.copy2(file_path, backup_path)

        # Locate the .text section for code injection
        code_section = next((s for s in binary.sections if s.name == ".text"), None)
        if not code_section:
            raise RuntimeError("No .text section found in the binary. This file might be malformed.")

        print(Fore.GREEN + "\n  Resolving required symbols...")

        # Resolve exported ordinals (varies by D2 version)
        if timestamp < VERSION_107_TIMESTAMP or timestamp == VERSION_106B_TIMESTAMP:
            # Versions 1.06 and 1.06b use these ordinals
            init_game_ord = resolve_exported_symbol(binary, 10017)  # Game initialization routine
            calc_time_ord = resolve_exported_symbol(binary, 10036)  # Time calculation routine
        else:
            # Versions 1.07 and higher use these ordinals
            init_game_ord = resolve_exported_symbol(binary, 10019)  # Game initialization routine
            calc_time_ord = resolve_exported_symbol(binary, 10055)  # Time calculation routine

        # Resolve Windows API imports
        init_cs_fn  = resolve_imported_symbol(binary, "InitializeCriticalSection")
        get_tick_fn = resolve_imported_symbol(binary, "GetTickCount")
        enter_cs_fn = resolve_imported_symbol(binary, "EnterCriticalSection")
        leave_cs_fn = resolve_imported_symbol(binary, "LeaveCriticalSection")

        # Locate internal logic and global state structures
        init_time_fn = locate_time_initializer(init_game_ord, binary, code_section)
        cs = locate_critical_section_struct(init_time_fn, init_cs_fn, binary, code_section)
        crt_time_fn, cache_region = locate_crt_time_and_cache_region(calc_time_ord, get_tick_fn, binary, code_section)

        # Use discovered cache region if available; otherwise fallback to address 0.
        cached_time = cache_region or 0
        cached_tick = cached_time + 0x4 if cache_region else 0

        # Print resolved addresses
        symbol_map = {
            # Imported Windows API functions
            "IAT:InitializeCriticalSection": init_cs_fn,
            "IAT:EnterCriticalSection":      enter_cs_fn,
            "IAT:LeaveCriticalSection":      leave_cs_fn,
            "IAT:GetTickCount":              get_tick_fn,

            # Exported ordinals from Fog.dll
            "ORD:InitGame":                  init_game_ord,
            "ORD:CalcTime":                  calc_time_ord,

            # Discovered internal function addresses
            "FUNC:InitTime":                 init_time_fn,
            "FUNC:msvcrt_time":              crt_time_fn,

            # Global state addresses
            "GLOB:CachedTime":               cached_time,
            "GLOB:CachedTickCount":          cached_tick,
            "GLOB:CriticalSection":          cs,
        }

        print(Fore.GREEN + "\n  Resolved symbols:")
        for name, addr in symbol_map.items():
            if not addr:
                raise ValueError(f"  {name} is zero or undefined. Cannot proceed without this address.")
            print_pretty(name, f"0x{addr:08X}", Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)

        # Generate replacement assembly for time init and time calc
        init_asm = init_time_asm(cs, init_cs_fn, crt_time_fn, cached_time, get_tick_fn, cached_tick)
        calc_asm = calc_time_asm(get_tick_fn, cached_tick, cs, enter_cs_fn, crt_time_fn, cached_time, leave_cs_fn)

        print(Fore.GREEN + "\n  Patching functions...")

        # Assemble and write patch code
        assembler = Ks(KS_ARCH_X86, KS_MODE_32)
        apply_patch(init_time_fn, init_asm, assembler, binary, code_section)
        apply_patch(calc_time_ord, calc_asm, assembler, binary, code_section)

        # Save the patched binary
        print()
        print_pretty("Saving patched binary to", file_path, Fore.GREEN, Style.BRIGHT + Fore.WHITE, 32, indent=2)
        binary.write(target_path)
        print()
        print_pretty("Status", "Success", Fore.GREEN, Style.BRIGHT + Fore.WHITE, 32, indent=2)
        return True

    except Exception as e:
        print_pretty("Error", f"Patching {file_path} failed: {e}", Fore.RED, Style.BRIGHT + Fore.WHITE, 30)
        # Roll back to the original if possible
        if os.path.exists(backup_path):
            print_pretty("Action", f"Restoring original file from '{backup_path}'.",
                         Fore.YELLOW, Style.BRIGHT + Fore.WHITE, 30)
            if not output_dir:
                shutil.copy2(backup_path, file_path)
        else:
            print_pretty("Warning", "No original backup found to restore from. The file might be corrupted.",
                         Fore.RED, Style.BRIGHT + Fore.WHITE, 30)
        print_pretty("Result", "Patching failed.", Fore.RED, Style.BRIGHT + Fore.WHITE, 30)
        return False

# endregion

# region: Main Execution Logic


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", help="Directory to write patched files to")
    args = parser.parse_args()

    target_file = "Fog.dll"
    print(Fore.CYAN + f"Searching for '{target_file}'...")

    # Step 1: Determine which Fog.dll files to patch:
    # - If --output-dir is specified, recursively search from the current directory,
    #   excluding the output directory itself.
    # - Otherwise, search only the current directory (non-recursively).
    found_files = []
    if args.output_dir:
        output_abs = os.path.abspath(args.output_dir)
        for root, _, files in os.walk("."):
            if os.path.abspath(root).startswith(output_abs):
                continue
            for file in files:
                if file.lower() == target_file.lower():
                    found_files.append(os.path.join(root, file))
    else:
        for file in os.listdir("."):
            if file.lower() == target_file.lower():
                found_files.append(file)

    failed_files = []

    # Step 2: Process discovered files (if any)
    if found_files:
        for file_path in found_files:
            if not patch_fog_dll(file_path, output_dir=args.output_dir):
                failed_files.append(file_path)

    # Step 3: Final summary and reporting
    print(Fore.WHITE + "\n--- Patching Summary ---")
    if not found_files:
        print(Fore.YELLOW + f"No '{target_file}' files were found. Nothing was processed.")
    elif failed_files:
        print(Fore.RED + "The following files failed to patch:")
        for file_path in failed_files:
            print(Fore.RED + f"  - {file_path}")
        print(Fore.YELLOW + "Please review the error messages above for details on each failure.")
    else:
        print(Fore.CYAN + f"Found {len(found_files)} instance(s) of '{target_file}'.")
        print(Fore.GREEN + "All found Fog.dll files were successfully processed.")
    print(Fore.WHITE + "Patching process complete.")
    return 0 if not failed_files else 1

# endregion


if __name__ == '__main__':
    sys.exit(main())
