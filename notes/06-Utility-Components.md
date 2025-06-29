# 6. Utility Components

This document covers the supporting components of the project: `main.cpp`, the `Disassembler` class, and the `Logger` class.

## 6.1. `main.cpp`: Application Entry Point

This file provides the `main` function, which serves as the entry point for the command-line application.

### 6.1.1. Responsibilities

-   **Command-Line Argument Parsing**: It is responsible for parsing the command-line arguments provided by the user.
-   **Input Validation**: It performs basic validation, such as ensuring an executable path is provided and that the file exists.
-   **Emulator Orchestration**: It instantiates the `Emulator` class and drives its main lifecycle (`initialize`, `start`).
-   **User Feedback**: It provides help messages and logs high-level status and error messages.

### 6.1.2. Implementation Details

-   It uses `argc` and `argv` for basic argument handling.
-   It supports `-h` and `--help` flags for displaying a usage message.
-   It leverages the C++17 `std::filesystem` library for robust path manipulation and validation (`std::filesystem::path`, `std::filesystem::exists`).
-   It carefully separates the directory path from the filename to pass them as distinct arguments to the `Emulator` constructor.
-   It returns an appropriate exit code (`0` for success, `-1` for failure) to the shell.

## 6.2. `Disassembler` Class

**File**: `src/Disassembler.cpp`

This class is a straightforward wrapper around the Capstone Engine.

### 6.2.1. Responsibilities

-   To provide on-demand disassembly of machine code from the emulated process.
-   To provide a register dump for debugging purposes.

### 6.2.2. Implementation Details

-   **`disassemble_at(uc_engine* uc, uint64_t rip)`**: This is the primary method.
    -   It reads 16 bytes of memory from the provided `rip` address within the Unicorn instance (`uc_mem_read`).
    -   It initializes a Capstone handle (`cs_open`) for the `CS_ARCH_X86`, `CS_MODE_64` architecture.
    -   It calls `cs_disasm` to perform the disassembly. It is configured to disassemble only a single instruction (`count = 1`).
    -   It prints the disassembled instruction's address, mnemonic, and operand string.
    -   It properly cleans up the Capstone resources (`cs_free`, `cs_close`).

-   **`print_registers(uc_engine* uc)`**: This is a debugging helper.
    -   It contains a static array of structs that maps Unicorn register IDs (`uc_x86_reg`) to their string names.
    -   It iterates through this array, reads each register's value from Unicorn using `uc_reg_read`, and prints the name and value in hexadecimal format.
    -   This function is called when the emulator encounters a fatal error to provide a snapshot of the CPU state at the time of the crash.

## 6.3. `Logger` Class

**File**: `src/Logger.cpp`

This is a simple, static utility class for logging color-coded messages to the console.

### 6.3.1. Responsibilities

-   To provide a centralized and consistent way to log messages.
-   To improve the readability of the emulator's output by using color to categorize messages.

### 6.3.2. Implementation Details

-   **`logf(Color color, const char* format, ...)`**: This is a static, variadic function that mimics `printf`.
    -   It first calls `get_color_code()` to print the ANSI escape sequence for the desired color.
    -   It then uses `va_list`, `va_start`, `vprintf`, and `va_end` to process the format string and variable arguments.
    -   Finally, it prints the ANSI reset code (`\033[0m`) to ensure the color does not "leak" to subsequent console output.

-   **`get_color_code(Color color)`**: This is a private static helper function.
    -   It uses a `switch` statement to map the `Color` enum to the corresponding ANSI color code string.
    -   `Color::DEFAULT` maps to the reset code.
