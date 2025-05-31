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

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_RET
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone.x86_const import X86_OP_MEM, X86_OP_IMM
from colorama import init, Fore, Style

import os
import shutil

# Initialize Colorama for colored CLI output
init(autoreset=True)

# --------------------------------------------------------------------------
# Utility Functions
# --------------------------------------------------------------------------


def print_aligned_message(label, value, label_color, value_color, align_width, indent=4):
    """
    Prints a colorized and aligned message with a label and its corresponding value.

    Args:
        label (str): The descriptive label text.
        value (str): The value associated with the label.
        label_color (colorama.Fore): The color for the label text.
        value_color (colorama.Fore): The color for the value text.
        align_width (int): The width allocated for aligning the label text.
        indent (int, optional): The number of spaces to indent the entire line. Defaults to 4.

    Returns:
        None
    """
    indent_str = " " * indent
    formatted_label = f"{label:<{align_width}}"
    print(f"{indent_str}{label_color}{formatted_label}{Style.RESET_ALL}: " +
          f"{value_color}{value}{Style.RESET_ALL}")


def resolve_symbol(binary, base, symbol):
    """
    Resolves an imported function (by name) or exported function (by ordinal) to its virtual address (VA).

    This function supports:
    - Imported functions: Matches the given name against the binary's import address table (IAT).
    - Exported functions: Matches the given ordinal against the export table.

    Args:
        binary (lief.PE.Binary): The LIEF PE binary object under analysis.
        base (int): The image base address of the binary in memory.
        export_table (lief.PE.Export): The export table of the binary.
        symbol (str | int): A string (import function name) or an integer (export ordinal).

    Returns:
        int: The resolved virtual address (VA) of the symbol.

    Raises:
        RuntimeError: If an ordinal is not found in the export table.
        TypeError: If `symbol` is neither a string nor an integer.
    """
    print_aligned_message("Resolving symbol", str(
        symbol), Fore.CYAN, Style.BRIGHT + Fore.WHITE, 30)

    if isinstance(symbol, str):
        # Iterate through import entries to find the function by name
        for entry in binary.imports:
            for function in entry.entries:
                if function.name and function.name.lower() == symbol.lower():
                    # For imports, return the address from the Import Address Table (IAT)
                    return base + function.iat_address
    elif isinstance(symbol, int):
        export_table = binary.get_export()  # Get the export directory
        # Calculate the index in the export table based on the ordinal base
        ordinal_base = export_table.ordinal_base
        ordinal_index = symbol - ordinal_base
        if ordinal_index < 0 or ordinal_index >= len(export_table.entries):
            raise RuntimeError(f"Ordinal {symbol} not found in export table.")
        # For exports, the address is an RVA (Relative Virtual Address),
        # so add the image base to get the VA.
        rva = export_table.entries[ordinal_index].address
        return base + rva
    else:
        raise TypeError("Symbol must be a string (import name) or an integer (ordinal).")


def disassemble_function(virtual_address, binary, base, code_section):
    """
    Disassembles a sequence of bytes from the specified code section using Capstone, starting at the given virtual
    address.

    Args:
        virtual_address (int): The virtual address (VA) where disassembly should begin.
        binary (lief.PE.Binary): The LIEF PE binary object.
        base (int): The image base address of the binary in memory.
        code_section (lief.PE.Section): The `.text` (code) section from which to read bytes.

    Returns:
        list[capstone.CsInsn]: A list of Capstone instruction objects representing
        the disassembled function code.

    Raises:
        ValueError: If the provided `virtual_address` falls outside the boundaries
        of the specified code section.
    """
    print_aligned_message("Disassembling function at",
                          f"0x{virtual_address:08X}", Fore.MAGENTA, Style.BRIGHT + Fore.WHITE, 30)

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


def apply_patch(virtual_address, asm_source, assembler, binary, base, code_section):
    """
    Assembles the provided x86 assembly source code into machine bytes using Keystone, and then injects these bytes into
    the target binary's `.text` section at the specified virtual address.

    This function is central to modifying the binary, replacing existing code with the restored pre-1.06 time caching
    logic.

    Args:
        virtual_address (int): The virtual address (VA) where the patch bytes
                               should be written.
        asm_source (str): A multi-line string containing the x86 assembly
                          code to be assembled.
        assembler (keystone.Ks): An initialized Keystone assembler instance.
        binary (lief.PE.Binary): The LIEF binary object to be patched.
        base (int): The image base address of the binary.
        code_section (lief.PE.Section): The `.text` (code) section of the binary.

    Raises:
        ValueError: If the assembled patch would extend beyond the boundaries
                    of the `code_section`.
    """
    print_aligned_message(
        "Applying patch at", f"0x{virtual_address:08X}", Fore.YELLOW, Style.BRIGHT + Fore.WHITE, 30)
    # Assemble the provided assembly source into machine code bytes
    patch_bytes = assembler.asm(asm_source, virtual_address)[0]

    print_aligned_message(
        "Patch size", f"{len(patch_bytes)} bytes", Fore.YELLOW, Style.BRIGHT + Fore.WHITE, 30)

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


def locate_time_initializer(address_time_init, binary, base, code_section):
    """
    Identifies the internal implementation of the time initializer routine exported by Fog.dll.

    The exported ordinals (e.g., 10017 or 10019) point directly to a routine that includes a `call` to the actual
    internal time initialization function. This function disassembles that routine and extracts the target address by
    identifying a `call` followed by a `lea` instruction, which commonly precedes setup logic using the return value.

    Args:
        address_time_init (int): The virtual address of the exported time initializer routine.
        binary (lief.PE.Binary): The parsed LIEF PE binary object.
        base (int): The image base address of the binary.
        code_section (lief.PE.Section): The `.text` (code) section from the binary.

    Returns:
        int: The virtual address (VA) of the internal time initialization function.

    Raises:
        RuntimeError: If the expected instruction pattern (a `call` followed by `lea`)
                      is not found in the disassembled routine.
    """
    print(Fore.GREEN + "\n  Locating time initializer function...")
    instructions = disassemble_function(
        address_time_init, binary, base, code_section)
    for idx, instr in enumerate(instructions):
        if instr.mnemonic == "lea":
            if idx > 0:
                previous_instr = instructions[idx - 1]
                if previous_instr.mnemonic == "call":
                    return previous_instr.operands[0].value.imm
    raise RuntimeError("Could not locate time initializer function pattern.")


def extract_time_cache_addresses(address_time_main, address_get_tick, binary, base, code_section):
    """
    Scans disassembled code to identify critical addresses related to Fog.dll's internal time caching logic.

    Given:
    - The virtual address of the exported main time function (e.g., ordinal 10036/10055), and
    - The IAT address of `GetTickCount`,

    This function performs the following steps:
    1. Identifies the internal time calculation function invoked by the exported function.
    2. Identifies the global memory address where the result of the time calculation is stored.
    3. Computes the addresses of the associated critical section structure (time_value - 0x18).
    4. Computes the address of the cached last tick count value (time_value + 0x4).

    Args:
        address_time_main (int): The virtual address of the main time retrieval function.
        address_get_tick (int): The IAT address of `GetTickCount`.
        binary (lief.PE.Binary): The parsed LIEF PE binary object for Fog.dll.
        base (int): The image base address of the binary in memory.
        code_section (lief.PE.Section): The `.text` section containing executable code.

    Returns:
        tuple[int, int, int, int]: A tuple containing:
            - The address of the internal time calculation function.
            - The address of the global cached time value.
            - The address of the global critical section structure.
            - The address of the cached last tick count value.

    Raises:
        RuntimeError: If expected instruction patterns are not found in the disassembly.
    """
    print(Fore.GREEN + "\n  Extracting time cache-related addresses...")
    instructions = disassemble_function(address_time_main, binary, base, code_section)
    addr_internal_time_func = None  # Address of the internal time function that calls GetLocalTime and GetSystemTime
    addr_cached_time_value = None
    addr_crit_section_struct = None
    addr_cached_tick_count = None

    for idx, instr in enumerate(instructions):
        # Pattern 1: Identify internal function address via `call` instruction
        # Look for a `push 0` followed by a `call` (common for __stdcall/__cdecl)
        if addr_internal_time_func is None and instr.mnemonic == "push" and instr.op_str == "0":
            if idx + 1 < len(instructions):
                next_instr = instructions[idx + 1]
                if next_instr.mnemonic == "call":
                    addr_internal_time_func = next_instr.operands[0].value.imm

        # Pattern 2: Identify cached time value via IAT reference to GetTickCount
        # Look for a `mov` instruction where the source operand is a memory address
        # pointing to the GetTickCount IAT entry, and a subsequent `mov` to an immediate.
        # This often indicates the location where the cached tick count or time value is set.
        if addr_cached_time_value is None and instr.mnemonic == "mov" and instr.operands and len(instr.operands) > 1 \
                and instr.operands[1].type == X86_OP_MEM and instr.operands[1].mem.disp == address_get_tick:
            if idx + 2 < len(instructions):
                next_instr = instructions[idx + 2]
                if next_instr.mnemonic == "mov" and next_instr.operands and len(
                        next_instr.operands) > 1 and next_instr.operands[1].type == X86_OP_IMM:
                    addr_cached_time_value = next_instr.operands[1].value.imm
                    addr_crit_section_struct = addr_cached_time_value - 0x18
                    addr_cached_tick_count = addr_cached_time_value + 0x4

    if addr_internal_time_func is None or addr_cached_time_value is None:
        raise RuntimeError("Could not extract all time cache-related addresses.")

    return (
        addr_internal_time_func,
        addr_cached_time_value,
        addr_crit_section_struct,  # Critical section struct is 0x18 bytes before the cached time value
        addr_cached_tick_count,  # Last tick count cache is 0x4 bytes after the cached time value
    )


def patch_fog_dll(file_path):
    print(Fore.WHITE + f"\n--- Processing: {file_path} ---")
    backup_path = file_path + ".bak"  # Define the path for the primary, definitive original backup

    try:
        # Backup management - always patch from a clean original. If an existing backup (.bak) is found, it means a
        # previous patch might have been applied. We restore the file from this backup to ensure we're always working on
        # the original, unpatched version.
        if os.path.exists(backup_path):
            print(Fore.YELLOW + f"  Found backup at '{backup_path}'. Restoring it to '{file_path}' before patching.")
            shutil.copy2(backup_path, file_path)
        else:
            shutil.copy2(file_path, backup_path)  # If no backup exists, create one from the current Fog.dll.

        # Binary loading - parse the binary and locate key sections.
        print(Fore.GREEN + "  Loading binary...")
        binary = lief.parse(file_path)
        if binary is None:
            raise RuntimeError("Failed to parse the binary. Please ensure it's a valid PE file.")

        # Base address where the DLL prefers to be loaded
        base = binary.optional_header.imagebase

    # Version detection - determine the game version from the PE timestamp.
        timestamp = binary.header.time_date_stamps

        # Define timestamps for known Diablo II Fog.dll versions. These values are derived from various D2 releases.
        VERSION_100_TIMESTAMP = 0x392ec7d4
        VERSION_101_TIMESTAMP = 0x3957d5f7
        VERSION_102_TIMESTAMP = 0x3966576f
        VERSION_103_TIMESTAMP = 0x3986136c
        VERSION_104B_TIMESTAMP = 0x3a3b5c92
        VERSION_104C_TIMESTAMP = 0x3a3b5c92
        VERSION_105_TIMESTAMP = 0x3a720eee
        VERSION_105B_TIMESTAMP = 0x3a79c9d4
        VERSION_106_TIMESTAMP = 0x3ade4595
        VERSION_106B_TIMESTAMP = 0x3b02c8ec
        VERSION_107_TIMESTAMP = 0x3af6e1d9
        VERSION_108_TIMESTAMP = 0x3b2eb277
        VERSION_109_TIMESTAMP = 0x3b7c4e0f
        VERSION_109B_TIMESTAMP = 0x3b7c4e0f
        VERSION_109D_TIMESTAMP = 0x3c06fcd3
        VERSION_100_BETA1_TIMESTAMP = 0x3f0472c7
        VERSION_100_BETA2_TIMESTAMP = 0x3f24b36e
        VERSION_110_TIMESTAMP = 0x3f8a5c4f
        VERSION_111_TIMESTAMP = 0x42e6c1f0
        VERSION_111B_TIMESTAMP = 0x43028af2
        VERSION_112A_TIMESTAMP = 0x483cb768
        VERSION_113_TIMESTAMP = 0x4b95c0aa
        VERSION_113C_TIMESTAMP = 0x4b95c0aa
        VERSION_113D_TIMESTAMP = 0x4e9de32b

        version_names = {
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

        current_version_name = version_names.get(timestamp, "Unknown")

        print_aligned_message("Fog.dll Version", current_version_name, Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)
        print_aligned_message("Timestamp", f"0x{timestamp:08X}", Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)

        # Check if patching is necessary based on the version timestamp.
        # Versions earlier than 1.06 already use the desired logic.
        if timestamp < VERSION_106_TIMESTAMP:
            print_aligned_message("Info", "Fog.dll is from a version earlier than 1.06. Patching is not necessary.",
                                  Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)
            # If no patching is needed, remove the temporary backup to clean up
            os.remove(backup_path)
            return True

        # Find the .text section, which contains the executable code
        code_section = next((s for s in binary.sections if s.name == ".text"), None)
        if not code_section:
            raise RuntimeError("No .text section found in the binary. This file might be malformed.")

        # Symbol resolution - resolve exports addresses.
        print(Fore.GREEN + "\n  Resolving required symbols...")

        # Exported functions from Fog.dll (resolved by ordinal; varies by D2 version)
        if timestamp < VERSION_107_TIMESTAMP or timestamp == VERSION_106B_TIMESTAMP:
            # Versions 1.06 and 1.06b use these ordinals
            addr_time_init_ord = resolve_symbol(binary, base, 10017)  # Time initialization routine
            addr_time_calc_ord = resolve_symbol(binary, base, 10036)  # Main time retrieval routine
        else:
            # Versions 1.07 and higher use these ordinals
            addr_time_init_ord = resolve_symbol(binary, base, 10019)  # Time initialization routine
            addr_time_calc_ord = resolve_symbol(binary, base, 10055)  # Main time retrieval routine

        # Imported Windows API functions (resolved by name from the export table or IAT)
        addr_init_crit_func = resolve_symbol(binary, base, "InitializeCriticalSection")
        addr_get_tick_func = resolve_symbol(binary, base, "GetTickCount")
        addr_enter_crit_func = resolve_symbol(binary, base, "EnterCriticalSection")
        addr_leave_crit_func = resolve_symbol(binary, base, "LeaveCriticalSection")

        # Address extraction - locate time logic and global state.
        addr_time_init_func = locate_time_initializer(addr_time_init_ord, binary, base, code_section)
        addr_internal_time_func, addr_cached_time_value, addr_crit_section_struct, addr_cached_tick_count = \
            extract_time_cache_addresses(addr_time_calc_ord, addr_get_tick_func, binary, base, code_section)

        # Display all resolved addresses for verification and debugging purposes
        symbol_map = {
            "InitializeCriticalSection_IAT": addr_init_crit_func,
            "GetTickCount_IAT": addr_get_tick_func,
            "EnterCriticalSection_IAT": addr_enter_crit_func,
            "LeaveCriticalSection_IAT": addr_leave_crit_func,
            f"Fog.dll_TimeInitOrd": addr_time_init_ord,
            f"Fog.dll_TimeCalcOrd": addr_time_calc_ord,
            "Fog.dll_InternalTime": addr_internal_time_func,
            "Fog.dll_TimeInit": addr_time_init_func,
            "Fog.dll_CachedTimeValue_Global": addr_cached_time_value,
            "Fog.dll_CriticalSection_Struct": addr_crit_section_struct,
            "Fog.dll_CachedTickCount_Global": addr_cached_tick_count,
        }

        print(Fore.GREEN + "\n  Resolved symbols:")
        for name, addr in symbol_map.items():
            if not addr:
                raise ValueError(f"  {name} is zero or undefined. Cannot proceed without this address.")
            print_aligned_message(name, f"0x{addr:08X}", Fore.BLUE, Style.BRIGHT + Fore.WHITE, 30)

        # Assembly for the main time retrieval function. This code replaces the logic at ordinal 10036/10055). It
        # reintroduces critical section protection and the older time calculation method.
        # '.byte` directives are used for specific opcodes that Keystone encodes differently to ensure byte-for-byte
        # compatibility with the originals.
        asm_main = f"""
            push esi                                        # Save ESI register
            call dword ptr [{addr_get_tick_func}]           # Call GetTickCount to get current tick
            mov edx, dword ptr [{addr_cached_tick_count}]   # Load last cached tick count into EDX
            .byte 0x8B, 0xF0                                # mov esi, eax (EAX holds current tick count from GetTickCount)
            .byte 0x2B, 0xC2                                # sub eax, edx (EAX = current_tick - last_cached_tick)
            cmp eax, 0x7FFFFFFF                             # Compare difference with 0x7FFFFFFF (large positive number)
            jbe skip                                        # If difference is less than or equal, skip update

            # --- Time update logic (entered if time difference is significant) ---
            push {addr_crit_section_struct}                 # Push address of Critical Section structure
            call dword ptr [{addr_enter_crit_func}]         # EnterCriticalSection (synchronize access)
            push 0                                          # Push 0 (argument for address_time_update_func)
            call {addr_internal_time_func}                  # Call internal time calculation function
            add esp, 4                                      # Clean up stack after call (for pushed 0)
            mov dword ptr [{addr_cached_time_value}], eax   # Store new calculated time value
            mov dword ptr [{addr_cached_tick_count}], esi   # Update last cached tick count with current tick from ESI
            push {addr_crit_section_struct}                 # Push address of Critical Section structure
            call dword ptr [{addr_leave_crit_func}]         # LeaveCriticalSection
        skip:
            # --- Time calculation for return value ---
            mov eax, dword ptr [{addr_cached_tick_count}]   # Load last cached tick count into EAX
            mov ecx, dword ptr [{addr_cached_time_value}]   # Load cached time value into ECX
            .byte 0x2B, 0xF0                                # sub esi, eax (ESI holds current tick, EAX last tick. ESI = current_tick - last_tick)
            mov eax, 0x10624DD3                             # Magic number for time scaling (specific to D2's timing algorithm)
            mul esi                                         # Multiply EAX by ESI (signed multiplication)
            .byte 0x8B, 0xC2                                # mov eax, edx (EDX holds the high part of the mul result, which is the scaled tick difference)
            pop esi                                         # Restore ESI register
            shr eax, 6                                      # Shift right by 6 (divide by 64) for further scaling
            .byte 0x03, 0xC1                                # add eax, ecx (Add scaled tick difference to cached time value)
            ret                                             # Return with calculated time in EAX
        """

        # Assembly for the time initialization function. This code replaces the logic at a sub-function called in
        # ordinal 10017/10019). It initializes the critical section and sets the initial cached time and tick count
        # values.
        asm_init = f"""
            push {addr_crit_section_struct}                 # Push address of Critical Section structure
            call dword ptr [{addr_init_crit_func}]          # InitializeCriticalSection
            push 0                                          # Argument for internal time func (usually 0)
            call {addr_internal_time_func}                  # Call internal time calculation function
            add esp, 4                                      # Clean up stack after call
            mov dword ptr [{addr_cached_time_value}], eax   # Store initial calculated time value
            call dword ptr [{addr_get_tick_func}]           # Get current tick count
            mov dword ptr [{addr_cached_tick_count}], eax   # Store initial cached tick count
            ret                                             # Return
        """

        # Patch injection - write assembled instructions into the binary.
        print(Fore.GREEN + "\n  Patching functions...")

        # Initialize the Keystone assembler for generating machine code from assembly
        assembler = Ks(KS_ARCH_X86, KS_MODE_32)

        apply_patch(addr_time_init_func, asm_init, assembler, binary, base, code_section)
        apply_patch(addr_time_calc_ord, asm_main, assembler, binary, base, code_section)

        # File saving - write the modified binary back to disk.
        print()
        print_aligned_message("Saving patched binary to", file_path, Fore.GREEN,
                              Style.BRIGHT + Fore.WHITE, 32, indent=2)
        binary.write(file_path)
        print()
        print_aligned_message("Status", "Success", Fore.GREEN, Style.BRIGHT + Fore.WHITE, 32, indent=2)
        return True

    except Exception as e:
        print_aligned_message("Error", f"Patching {file_path} failed: {e}", Fore.RED, Style.BRIGHT + Fore.WHITE, 30)
        # Roll back to the original if possible
        if os.path.exists(backup_path):
            print_aligned_message(
                "Action", f"Restoring original file from '{backup_path}'.", Fore.YELLOW, Style.BRIGHT + Fore.WHITE, 30)
            shutil.copy2(backup_path, file_path)
        else:
            print_aligned_message(
                "Warning", "No original backup found to restore from. The file might be corrupted.",
                Fore.RED, Style.BRIGHT + Fore.WHITE, 30)
        print_aligned_message("Result", "Patching failed.", Fore.RED, Style.BRIGHT + Fore.WHITE, 30)
        return False

# --------------------------------------------------------------------------
# Main Execution
# --------------------------------------------------------------------------


if __name__ == "__main__":
    target_file = "Fog.dll"
    print(Fore.CYAN + f"Searching for '{target_file}' in current directory and subdirectories...")

    found_files = []
    # Step 1: Recursively search for all Fog.dll files
    for root, _, files in os.walk("."):
        for file in files:
            if file.lower() == target_file.lower():
                found_files.append(os.path.join(root, file))

    failed_files = []

    # Step 2: Report and process discovered files
    if not found_files:
        print(Fore.YELLOW + f"No '{target_file}' found in the current directory or its subdirectories.")
    else:
        print(Fore.CYAN + f"Found {len(found_files)} instances of '{target_file}'.")
        for f_path in found_files:
            if not patch_fog_dll(f_path):
                failed_files.append(f_path)

    # Step 3: Final summary
    print(Fore.WHITE + "\n--- Patching Summary ---")
    if failed_files:
        print(Fore.RED + "The following files failed to patch:")
        for f_path in failed_files:
            print(Fore.RED + f"  - {f_path}")
        print(Fore.YELLOW + "Please review the error messages above for details on each failure.")
    else:
        print(Fore.GREEN + "All found Fog.dll files were successfully processed.")
    print(Fore.WHITE + "Patching process complete.")
