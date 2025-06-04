#pragma once

#include <unicorn/unicorn.h>
#include <iostream>
#include <LIEF/PE.hpp>
#include <dbghelp.h>
#include <windows.h>
#include <string>
#include <vector>
#include <winternl.h>
#include "PELoader.hpp"


#define STACK_ADDRESS 0x2000000
#define STACK_SIZE (2 * 1024 * 1024)
#define PAGE_SIZE 0x1000
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000

constexpr uint64_t GS_BASE = 0x7FFDF0000000;



struct BinaryInfo {
    std::string name;
    uint64_t base;
    uint64_t size;
};

struct HookContext;

class Emulator {
    std::vector<BinaryInfo> loaded_binaries;
    PELoader peloader;
    uc_engine* uc;

public:
    uint64_t main_code_start = 0;
    uint64_t main_code_end = 0;
    std::string main_binary_name;
    uint64_t next_free_address = 0x150000000;

    Emulator();
    ~Emulator();

    uc_engine* get_uc() const;

    size_t align_up(size_t size, size_t alignment);

    void set_code_bounds(uint64_t start, uint64_t end, const std::string& binary_name);

    uint64_t reserve_memory(size_t size, int perms = UC_PROT_ALL);

    PVOID GetPebFromTeb();

    void map_pe_binary(const LIEF::PE::Binary& binary, uint64_t load_base = 0, std::string name = "");

    void setup_stack();

    void map_kuser_shared_data();

    void setup_hooks(void* context);

    void set_entry_point(uint64_t entry_point);

    BinaryInfo* find_binary_by_address(uint64_t address);

    void emu_ret();

    std::string get_function_name_from_pdb(const std::string& dll_path, uint64_t rva);

    void start_emulation(uint64_t start_addr);

    bool isGsSegment(uint64_t addr);

    void CopyTebPebToBuffer(uint8_t* tebBuf, size_t tebSize, uint8_t* pebBuf, size_t pebSize);

    void setup_TEB_PEB();

    static bool hook_mem_read(uc_engine* uc, uc_mem_type type, uint64_t address,int size, int64_t value, void* user_data);

    static bool hook_mem_read_unmaped(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
    
    static void code_hook_cb(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

    void is_hooked(uc_err err, std::string HookName);
};
