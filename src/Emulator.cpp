#include "../headers/Emulator.hpp"
#include "Disassembler.cpp"
#include "Logger.cpp"
#include <codecvt>

Emulator::Emulator(const std::string& exePath, const std::string& exeName)
    : exeName(exeName),
    wExeName(exeName.begin(), exeName.end()),
    loader(std::wstring(exePath.begin(), exePath.end()) + wExeName) {
}

Emulator::~Emulator() {
    if (unicorn) {
        uc_close(unicorn);
        Logger::logf(Logger::Color::GREEN, "[+] Unicorn engine closed. Instruction count: %llu", instruction_count);
    }
}

void Emulator::hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    Emulator* self = static_cast<Emulator*>(user_data);
    self->instruction_count++;
    Logger::logf(Logger::Color::CYAN, "[+] Instruction @ 0x%llx (size: %u)", address, size);
}

bool Emulator::hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void* user_data) {
    Emulator* self = static_cast<Emulator*>(user_data);

    uint64_t pageStart = address & ~0xFFF;

    Logger::logf(Logger::Color::YELLOW, "[!] Invalid memory access @ 0x%llx (type: %d) -> trying to map page 0x%llx", address, type, pageStart);

    if (!self->loader.MapSingleMemoryPageToUnicorn(uc, pageStart)) {
        Logger::logf(Logger::Color::RED, "[-] Failed to dynamically map page at 0x%llx", pageStart);
        return false;  // do not retry access
    }

    Logger::logf(Logger::Color::GREEN, "[+] Successfully mapped missing page @ 0x%llx", pageStart);
    return true;  // retry memory access
}

void Emulator::hook_code_block(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    Emulator* self = static_cast<Emulator*>(user_data);
    self->instruction_count++;
    std::wstring moduleName = self->loader.GetModuleNameByAddress(address);
    std::string funcName = self->loader.GetExportedFunctionNameByAddress(address);
    if (funcName != "") {
        Logger::logf(Logger::Color::CYAN, "[+] %s", funcName.c_str());
    }

}

bool Emulator::initialize() {
    Logger::logf(Logger::Color::GREEN, "[+] Initializing Unicorn Engine...");

    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &unicorn);
    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to initialize Unicorn engine: %s", uc_strerror(err));
        return false;
    }

    if (!loader.LoadAndInspect(unicorn)) {
        Logger::logf(Logger::Color::RED, "[-] Failed to create and debug process");
        return false;
    }

    loader.LoadAllMemoryRegionsToUnicorn(unicorn);
    Logger::logf(Logger::Color::GREEN, "[+] Memory regions loaded into Unicorn.");

    return true;
}

bool Emulator::start() {

    uc_hook trace_hook_block;

    // uc_hook trace_hook;

    uc_err err = uc_hook_add(unicorn, &trace_hook_block, UC_HOOK_BLOCK, (void*)hook_code_block, this, 1, 0);

    // uc_err err = uc_hook_add(unicorn, &trace_hook, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);

    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to add code hook: %s", uc_strerror(err));
        return false;
    }


    uc_hook invalid_mem_hook;
    err = uc_hook_add(unicorn, &invalid_mem_hook,
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
        (void*)hook_mem_invalid, this, 1, 0);

    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to add invalid memory hook: %s", uc_strerror(err));
        return false;
    }

    uint64_t startAddr;
    uc_reg_read(unicorn, UC_X86_REG_RIP, &startAddr);
    Logger::logf(Logger::Color::CYAN, "[+] Starting emulation from RIP: 0x%llx", startAddr);

    err = uc_emu_start(unicorn, startAddr, 0, 0, 0);
    if (err != UC_ERR_OK) {
        uint64_t rip;
        uc_reg_read(unicorn, UC_X86_REG_RIP, &rip);
        Disassembler disassembler;
        disassembler.disassemble_at(unicorn, rip);
        disassembler.print_registers(unicorn);
        Logger::logf(Logger::Color::RED, "[-] Unicorn emulation error: %s at RIP: 0x%llx From : %ls", uc_strerror(err), rip, loader.GetModuleNameByAddress(rip).c_str());
        return false;
    }

    uint64_t rip;
    uc_reg_read(unicorn, UC_X86_REG_RIP, &rip);
    Logger::logf(Logger::Color::GREEN, "[+] Unicorn emulation finished successfully at RIP: 0x%llx", rip);
    return true;
}
