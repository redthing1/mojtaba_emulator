# 5. `Emulator` Class: A Deep Dive

**Files**: `src/Emulator.cpp`, `headers/Emulator.hpp`

## 5.1. Overview

If the `ProcessLoader` is the bridge to the native world, the `Emulator` class is the master of the emulated world. It owns and orchestrates the Unicorn Engine instance, using Unicorn's powerful hooking capabilities to instrument, analyze, and control the execution of the target program.

## 5.2. Core Responsibilities

1.  **Emulation Lifecycle Management**: It initializes, starts, and cleans up the Unicorn Engine.
2.  **Instrumentation via Hooks**: It registers and manages a suite of callback hooks that are triggered on various CPU events (code execution, memory access, etc.).
3.  **Hybrid Execution Logic**: It contains the high-level logic for the "world-switching" mechanism that handles API calls.
4.  **Analysis and Logging**: It coordinates the `Logger` and `Disassembler` to provide a coherent and detailed stream of information about the program's behavior.

## 5.3. Unicorn Hooks: The Core of Instrumentation

The power of the `Emulator` class comes from its use of Unicorn hooks. These are callback functions that Unicorn invokes when certain events occur during emulation. The `Emulator` class registers its static methods as these callbacks, passing `this` as the `user_data` pointer, which allows the static callbacks to operate on the `Emulator` instance.

### `hook_mem_invalid` (UC_HOOK_MEM_*_UNMAPPED)

-   **Trigger**: Fired when the CPU attempts to read, write, or fetch code from a memory address that is not currently mapped in Unicorn.
-   **Purpose**: This is the cornerstone of the **on-demand paging** system.
-   **Mechanism**:
    1.  The hook is triggered with the invalid `address`.
    2.  It immediately calls `loader.MapSingleMemoryPageToUnicorn(uc, address)`.
    3.  The `ProcessLoader` then reads the corresponding page from the live target process and maps it into Unicorn.
    4.  The hook returns `true`, which signals to Unicorn that the fault has been handled and the instruction that caused the fault should be re-executed. This time, the memory will be present, and execution will continue seamlessly.

### `hook_code_block` (UC_HOOK_BLOCK)

-   **Trigger**: Fired when Unicorn is about to execute a new basic block of instructions.
-   **Purpose**: This is the primary trigger for the **hybrid API call** mechanism.
-   **Mechanism**:
    1.  It gets the `address` of the new basic block.
    2.  It calls `loader.GetModuleNameByAddress(address)` to determine which module this code belongs to.
    3.  **Crucial Logic**: It compares the current module name to the name of the main executable (`wExeName`).
    4.  If the code is **outside** the main executable, it assumes an API call is being made to a DLL.
    5.  It then calls `ReloadAtAddress()` to initiate the "world switch" to native execution.

### `ReloadAtAddress(uint64_t address)`

This function orchestrates the temporary hand-off of execution to the native OS.

1.  It reads the **return address** from the top of the emulated stack (`Poi(UC_X86_REG_RSP)`). This is the address where the native code will return to after the API call is complete.
2.  It calls `loader.SetBreakpoint()` to place a software breakpoint on this return address in the **live process**.
3.  It calls `loader.resume_program()`, which issues a `ContinueDebugEvent` to the OS, letting the live process run freely.
4.  It immediately calls `loader.DebugLoop(unicorn)`. This is a blocking call that enters the debugger event loop, waiting for the return breakpoint to be hit.
5.  **Native Execution**: The OS now takes over and executes the API call natively.
6.  **Return and Re-Sync**: When the API call is finished, the live process attempts to return, hitting our breakpoint. The `DebugLoop` catches this event, and as part of its logic, it **re-synchronizes all memory and registers** from the live process back to the Unicorn instance. This ensures any changes made by the API call (e.g., a buffer being filled) are reflected in the emulator.
7.  Execution is now seamlessly handed back to Unicorn.

### `hook_mem_read` / `hook_mem_write` (UC_HOOK_MEM_READ/WRITE)

-   **Trigger**: Fired on every memory read or write operation.
-   **Purpose**: Detailed memory access logging and analysis.
-   **Mechanism**: These hooks are designed to be informative but not overly verbose.
    -   They ignore accesses to the stack, as these are extremely frequent and usually not interesting.
    -   They contain specific logic to identify accesses to well-known, important Windows data structures:
        -   **`KUSER_SHARED_DATA`**: By checking if the address is in the `0x7FFE0000` range.
        -   **`TEB`**: By checking if the address is relative to the `GS_BASE` register.
        -   **`PEB`**: By first reading the PEB address from the TEB (`GS:[0x60]`) and then checking if the access falls within that region.
    -   For these special regions, it uses the offset maps (`kuser_shared_data_offsets`, etc.) to print a human-readable description of the field being accessed, providing valuable context.

### `hook_cpuid` / `hook_syscall` (UC_HOOK_INSN)

-   **Trigger**: Fired when a specific instruction is executed.
-   **Purpose**: To flag the use of instructions that are often used for anti-analysis, fingerprinting, or transitioning to kernel mode.
-   **Mechanism**: They are registered with the specific instruction codes (`UC_X86_INS_CPUID`, `UC_X86_INS_SYSCALL`). When triggered, they simply log the event and the address where it occurred.
