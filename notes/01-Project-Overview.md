# 1. Project Overview

This document provides a high-level technical overview of the hybrid emulator, its architecture, and its core operational principles.

## 1.1. Introduction

This project is a **hybrid user-mode emulator for 64-bit Windows Portable Executables (PE)**. It is designed for dynamic analysis of software in a controlled environment. The term "hybrid" refers to its architectural model, which combines a traditional CPU emulator with a live, debugged instance of the target process. This allows the system to perform fine-grained, instruction-level emulation while strategically offloading complex or well-understood operations (like system calls) to the host OS.

The primary goal is to create an analysis platform that is both powerful and pragmatic. It avoids the immense complexity of full-system emulation (which would require re-implementing the entire Windows kernel and its APIs) by letting the real OS handle what it does best.

## 1.2. Core Technologies

-   **CPU Emulation**: [**Unicorn Engine**](https://www.unicorn-engine.org/) is used for the core CPU emulation. It provides a robust API for executing machine code, managing CPU state (registers), and handling memory.
-   **Disassembly**: [**Capstone Engine**](https://www.capstone-engine.org/) is used for disassembling machine code. This is crucial for logging, debugging, and providing context during instruction-level tracing.
-   **Process Control**: The **Windows Debug API** is used to launch, monitor, and interact with the live target process. Key functions include `CreateProcessW`, `WaitForDebugEvent`, `ReadProcessMemory`, and `GetThreadContext`.

## 1.3. Hybrid Emulation Model

The core of the project is its hybrid execution model. Here's how it works:

1.  **Seeding Phase (Initialization)**:
    -   A target executable is launched as a new process using the Windows Debug API. It is created in a **suspended state** and attached to the emulator as a **debugger**.
    -   A software breakpoint (`0xCC`) is placed at the program's initial entry point (either a TLS callback or the main PE entry point).
    -   The process is resumed. It runs natively for a brief moment until it hits the breakpoint, triggering a debug exception.
    -   At this point, the process is perfectly paused at its very first instruction. The emulator captures a complete snapshot of its initial state: the full register context of the main thread and a copy of all committed pages in its virtual address space.
    -   This captured state is then used to "seed" a Unicorn Engine instance. The Unicorn CPU's registers are set, and its memory is populated to be an exact replica of the live process.

2.  **Emulation Phase (Unicorn Execution)**:
    -   The emulator starts executing the program's code instruction-by-instruction within the Unicorn Engine.
    -   A series of **hooks** are registered with Unicorn to instrument the execution. These hooks are the primary mechanism for analysis and for managing the hybrid model.

3.  **World-Switching (Hybrid Operations)**:
    -   **On-Demand Paging**: If the emulated code tries to access a memory address that wasn't mapped during the initial seeding (e.g., memory allocated on the heap or a newly loaded DLL), Unicorn triggers an exception. A hook catches this, reads the required memory page from the **live process**, maps it into Unicorn, and resumes the emulation. This is a form of demand-driven memory synchronization.
    -   **API Call Offloading**: When the emulated code calls a function in an external library (e.g., `kernel32.dll!CreateFileW`), a hook detects this transition. Instead of attempting to emulate the entire Windows API, the emulator performs a "world switch":
        a. It sets a breakpoint at the **return address** of the API call in the live process.
        b. It resumes the live process, allowing the Windows kernel to execute the API call natively.
        c. It waits for the return breakpoint to be hit.
        d. Once the native call completes, the emulator re-synchronizes the state (registers and any memory modified by the API call) from the live process back to the Unicorn instance and resumes emulation.

## 1.4. Execution Flow Diagram

```
+-------------------------+
|      main.cpp         |
| (Parse Args, Init)      |
+-----------+-------------+
            |
            v
+-----------+-------------+
|   Emulator::initialize  |
+-----------+-------------+
            |
            v
+-----------+-------------+
| ProcessLoader::Load...  |
| - CreateProcessW        |
| - SetBreakpointAtStartup|
| - DebugLoop (wait)      |
| - GetRegisters          |
| - LoadAllMemory...      |
+-----------+-------------+
            | (Unicorn is now seeded)
            v
+-----------+-------------+
|     Emulator::start     |
| - uc_hook_add(...)      |
| - uc_emu_start()        |
+-----------+-------------+
            |             +------------------------------------+
            |             |           EMULATION LOOP           |
            |             +------------------------------------+
            |             |                                    |
+-----------v-------------+<--+ (Resume)                         |
| (Unicorn executes code) |   |                                  |
+-----------+-------------+   |                                  |
            |                 |                                  |
+-----------v-------------+   |                                  |
|    Is access valid?     |---(No)--->+-------------------------+  |
+-----------+-------------+           | hook_mem_invalid        |  |
            | (Yes)                   | - MapSingleMemoryPage() |  |
            v                         +-----------+-------------+  |
+-----------v-------------+                       |                |
| Is RIP in main .exe?    |---(No)--->+-----------+-------------+  |
+-----------+-------------+           | hook_code_block         |  |
            | (Yes)                   | - ReloadAtAddress()     |  |
            |                         |   - Set BP on ret       |  |
            +-------------------------+   - Resume native proc  |  |
                                      |   - Wait for BP hit     |  |
                                      |   - Re-sync state       |  |
                                      +-----------+-------------+  |
                                                  |                |
                                                  +----------------+
```
