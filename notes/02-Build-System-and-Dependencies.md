# 2. Build System and Dependencies

This document provides detailed information about the project's dependencies, the CMake build system, and the steps required to compile the emulator.

## 2.1. Dependencies

The project has two core external dependencies, which are managed as Git submodules. This ensures that the correct versions of these libraries are used for the build.

-   **Unicorn Engine**: A lightweight, multi-platform, multi-architecture CPU emulator framework.
    -   **Role**: Provides the core CPU emulation capabilities, including register and memory management, and the hooking mechanism for instrumentation.
    -   **Location**: `deps/unicorn`
    -   **Link**: [https://github.com/unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn)

-   **Capstone Engine**: A lightweight, multi-platform, multi-architecture disassembly framework.
    -   **Role**: Used to disassemble machine code at runtime for logging and analysis.
    -   **Location**: `deps/capstone`
    -   **Link**: [https://github.com/capstone-engine/capstone](https://github.com/capstone-engine/capstone)

### 2.1.1. Acquiring Dependencies

To clone the repository and its dependencies, use the `--recursive` flag:

```bash
# Clones the main repo and initializes/updates submodules in one step
git clone --recursive <repository_url>
```

If the repository is already cloned, initialize the submodules manually:

```bash
git submodule update --init --recursive
```

## 2.2. Build System: CMake

The project uses [CMake](https://cmake.org/) for cross-platform build automation.

### 2.2.1. `CMakeLists.txt`

This is the primary build script. Here are its key sections:

-   `cmake_minimum_required(VERSION 3.8)`: Specifies the minimum required version of CMake.
-   `project("emulator")`: Defines the project name.
-   `add_executable(emulator ...)`: Defines the main executable target and lists its source files:
    -   `main.cpp`
    -   `src/Emulator.cpp`
    -   `src/Loader.cpp`
    -   `src/Disassembler.cpp`
    -   `src/Logger.cpp`
-   `set_property(TARGET emulator PROPERTY CXX_STANDARD 20)`: Sets the C++ language standard to C++20.
-   `if (WIN32)`: A conditional block for Windows-specific settings.
    -   `target_link_libraries(emulator dbghelp)`: Links the executable against `dbghelp.lib`, which is required for using the Windows Debug API effectively.
-   `add_subdirectory(deps/...)`: This command tells CMake to descend into the `unicorn` and `capstone` subdirectories and build them as part of the main project.
-   `target_link_libraries(emulator unicorn capstone)`: Links the `emulator` executable against the compiled `unicorn` and `capstone` libraries.

### 2.2.2. `CMakePresets.json`

This file provides a modern, convenient way to configure CMake builds without needing to manually specify command-line arguments. It is designed for use with Visual Studio, VS Code, or the CMake command-line interface.

-   **`windows-base`**: A hidden, base preset that defines common settings for Windows builds:
    -   **`generator`**: `Ninja` (a fast, parallel build system).
    -   **`binaryDir`**: Sets the output directory for build files to `${sourceDir}/out/build/${presetName}`.
    -   **`installDir`**: Sets the installation directory to `${sourceDir}/out/install/${presetName}`.
    -   **`cacheVariables`**: Specifies the C and C++ compilers as `cl.exe` (the MSVC compiler).
-   **Concrete Presets**: The file defines four user-visible presets that inherit from `windows-base`:
    -   `x64-debug` (default)
    -   `x64-release`
    -   `x86-debug`
    -   `x86-release`
    These presets configure the architecture (`x64` or `x86`) and the build type (`Debug` or `Release`).

## 2.3. Building the Project

### Prerequisites

-   CMake (version 3.8+)
-   A C++20 compliant compiler (e.g., Visual Studio 2019 or later)
-   Ninja (recommended, usually included with Visual Studio)

### Build Steps

1.  **Open a developer command prompt** that has the C++ compiler and CMake in its PATH (e.g., "x64 Native Tools Command Prompt for VS 2022").

2.  **Navigate to the project root directory**.

3.  **Configure CMake** using a preset:
    ```bash
    # This will create the build directory at out/build/x64-debug
    cmake --preset x64-debug
    ```

4.  **Run the build**:
    ```bash
    # CMake will invoke Ninja to compile the project
    cmake --build --preset x64-debug
    ```

5.  **Run the emulator**:
    The compiled executable will be located at `out/build/x64-debug/emulator.exe`.
    ```bash
    ./out/build/x64-debug/emulator.exe "C:\path\to\your\executable.exe"
    ```
