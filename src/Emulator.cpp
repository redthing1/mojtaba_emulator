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
void Emulator::hook_mem_read(uc_engine* uc, uint64_t address, int size, int64_t value, void* user_data) {
    uint64_t rip, rsp;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);


    Emulator* self = static_cast<Emulator*>(user_data);

    if (address >= rsp && address < rsp + 0x1000) {
        // Stack read - skip
        return;
    }
    if (address >= 0x00000007FFE0000 && address < 0x00000007FFE0000 + 0x1000) {
        Logger::logf(Logger::Color::YELLOW, "[KUSER_SHARED_DATA] RIP: 0x%llx ", rip);
        return;
    }

 
}



void Emulator::hook_mem_write(uc_engine* uc, uint64_t address, int size, int64_t value, void* user_data) {
        uint64_t rip, rsp;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);


        if (address >= rsp && address < rsp + 0x1000) {
            return;
        }
  //  Logger::logf(Logger::Color::YELLOW, "[MEM-WRITE] Address: 0x%llx  ", rip);
}


void Emulator::hook_cpuid(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    uint64_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    Logger::logf(Logger::Color::YELLOW, "[CPUID] Executed at 0x%llx", rip);
}


void Emulator::hook_syscall(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    uint64_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    Logger::logf(Logger::Color::YELLOW, "[in Line SYSCALL] Executed at 0x%llx", rip);
}
void Emulator::hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    Emulator* self = static_cast<Emulator*>(user_data);
    self->instruction_count++;
    Disassembler dis;
    uint64_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    dis.disassemble_at(uc, rip);
   
    Logger::logf(Logger::Color::YELLOW, "[RPS]: 0x%llx", self->Poi(UC_X86_REG_RSP));
}

bool Emulator::hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void* user_data) {
    Emulator* self = static_cast<Emulator*>(user_data);

    uint64_t pageStart = address & ~0xFFF;

   // Logger::logf(Logger::Color::YELLOW, "[!] Invalid memory access @ 0x%llx (type: %d) -> trying to map page 0x%llx", address, type, pageStart);

    if (!self->loader.MapSingleMemoryPageToUnicorn(uc, pageStart)) {
        Logger::logf(Logger::Color::RED, "[-] Failed to dynamically map page at 0x%llx", pageStart);
        return false;  // do not retry access
    }

  //  Logger::logf(Logger::Color::GREEN, "[+] Successfully mapped missing page @ 0x%llx", pageStart);
    return true;  // retry memory access
}

void Emulator::hook_code_block(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    Emulator* self = static_cast<Emulator*>(user_data);
    self->instruction_count++;
    std::wstring moduleName = self->loader.GetModuleNameByAddress(address);
    std::string funcName = self->loader.GetExportedFunctionNameByAddress(address);
    if (funcName != "") {
        Logger::logf(Logger::Color::CYAN, "[+] %s", funcName.c_str());
    self->ReloadAtAddress(self->Poi(UC_X86_REG_RSP));
    }


}
void Emulator::ReloadAtAddress(uint64_t address) {
    
    loader.RemoveBreakpoint();
    loader.SetBreakpoint((void*)address);
    loader.resume_program();
    loader.DebugLoop(unicorn);

}

uint64_t Emulator::Poi(uc_x86_reg reg) {
    uint64_t addr = 0;
    if (uc_reg_read(unicorn, reg, &addr) != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to read register");
        return 0;
    }

    uint64_t value = 0;
    if (uc_mem_read(unicorn, addr, &value, sizeof(uint64_t)) != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to read memory at 0x%llx", addr);
        return 0;
    }

    return value;
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


    uc_err err = uc_hook_add(unicorn, &trace_hook_block, UC_HOOK_BLOCK, (void*)hook_code_block, this, 1, 0);
    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to add code BLOCK hook : %s", uc_strerror(err));
        return false;
    }
    // uc_hook trace_hook;

     // err = uc_hook_add(unicorn, &trace_hook, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);

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

    uc_hook mem_read_hook;
    err = uc_hook_add(unicorn, &mem_read_hook, UC_HOOK_MEM_READ, (void*) hook_mem_read, this, 1, 0);
    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to add memory read hook: %s", uc_strerror(err));
    }

    //uc_hook mem_write_hook;
    //err = uc_hook_add(unicorn, &mem_write_hook, UC_HOOK_MEM_WRITE, (void*)hook_mem_write, this, 1, 0);
   // if (err != UC_ERR_OK) {
   //     Logger::logf(Logger::Color::RED, "[-] Failed to add memory write hook: %s", uc_strerror(err));
   // }

    uc_hook cpuid_hook;
    err = uc_hook_add(unicorn, &cpuid_hook, UC_HOOK_INSN, (void*)hook_cpuid, this, 1, 0);


    // SYSCALL instruction
    uc_hook syscall_hook;
    err = uc_hook_add(unicorn, &syscall_hook, UC_HOOK_INSN, (void*)hook_syscall, this, 1, 0);



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
