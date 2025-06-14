#pragma once

#include <string>
#include <unicorn/unicorn.h>
#include "Loader.hpp"

class Emulator {
public:
    Emulator(const std::string& exePath, const std::string& exeName);
    ~Emulator();

    bool initialize();
    bool start();

private:
    static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static void hook_code_block(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

    std::string exeName;
    std::wstring wExeName;
    ProcessLoader loader;
    uc_engine* unicorn = nullptr;
    uint64_t instruction_count = 0;
};
