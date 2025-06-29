# 3. Core Data Structures

This document provides a reference for the key data structures used within the emulator. These include custom structures for managing the emulator's state and representations of important Windows internal structures.

## 3.1. Custom Emulator Structures

These structures are defined in `headers/Loader.hpp`.

### `struct CpuRegisters`

-   **Purpose**: To hold a complete snapshot of the CPU register state.
-   **Definition**:
    ```cpp
    struct CpuRegisters {
        uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
        uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
        uint64_t rip, eflags;

        uint64_t xmm[16][16]; // Note: This is not correctly defined for XMM registers
    };
    ```
-   **Usage**: An instance of this struct is populated by `ProcessLoader::GetRegisters()` by reading the `CONTEXT` of the debugged thread. It serves as a portable container for register values before they are written to the Unicorn Engine.
-   **Note**: The `xmm` member is incorrectly defined as a 2D array of `uint64_t`. XMM registers are 128-bit (16 bytes). A more accurate representation would be `unsigned char xmm[16][16];` or a similar 128-bit structure.

### `struct DebugState`

-   **Purpose**: To store the state of the last received debug event.
-   **Definition**:
    ```cpp
    struct DebugState {
        DEBUG_EVENT lastEvent;
        bool hasPendingEvent = false;
    };
    ```
-   **Usage**: This is used in the hybrid API call mechanism. When an API call is offloaded to the native process, the emulator needs to resume the process. `ContinueDebugEvent` requires the `dwProcessId` and `dwThreadId` from the original event that caused the debugger to break. This struct caches that event so it can be used later to resume execution.

### `struct MemoryRegion`

-   **Purpose**: To represent a contiguous region of memory in the target process.
-   **Definition**:
    ```cpp
    struct MemoryRegion {
        uint64_t base;
        size_t size;
        std::string name;

        MemoryRegion(uint64_t b, size_t s, const std::string& n = "") : base(b), size(s), name(n) {}
    };
    ```
-   **Usage**: The `ProcessLoader` maintains a `std::vector<MemoryRegion> memoryRegions_` to keep track of all memory regions that have been mapped into the Unicorn Engine. This is used to identify modules by address and to prevent double-mapping of memory pages.

## 3.2. Windows Internal Structures

The emulator defines several constants and maps to identify and log accesses to key Windows data structures. These are defined in `headers/Emulator.hpp`.

### `KUSER_SHARED_DATA`

-   **Description**: A page of memory mapped at a fixed address (`0x7FFE0000` in user mode) that is shared between the kernel and all user-mode processes. It contains global system information like system time, processor features, and debugger status.
-   **Implementation**: A `std::map<uint64_t, std::string> kuser_shared_data_offsets` maps the offsets within this structure to the names of the corresponding fields.
-   **Usage**: The `hook_mem_read` function checks if a memory access falls within the `KUSER_SHARED_DATA` range. If it does, it uses this map to log a descriptive message about which field is being read (e.g., `[KUSER_SHARED_DATA] Reading (NtBuildNumber)`).

### `TEB` (Thread Environment Block)

-   **Description**: A data structure that stores information about the current thread. It is accessed via the `GS` segment register in 64-bit processes.
-   **Implementation**: A `std::map<uint64_t, std::string> teb_offsets` maps offsets within the TEB to field names.
-   **Usage**: The `hook_mem_read` function checks if a memory access is relative to the `GS_BASE` register. If so, it logs the access with the field name from the map (e.g., `[TEB] Reading (ProcessEnvironmentBlock (PEB*))`)

### `PEB` (Process Environment Block)

-   **Description**: A data structure that contains information about the current process, such as the list of loaded modules, process parameters, and whether a debugger is attached.
-   **Implementation**: A `std::map<uint64_t, std::string> peb_offsets` maps offsets within the PEB to field names.
-   **Usage**: The `hook_mem_read` function first reads the address of the PEB from the TEB (`GS:[0x60]`). It then checks if memory accesses fall within the PEB's memory range and logs them accordingly (e.g., `[PEB] Reading (BeingDebugged)`).
