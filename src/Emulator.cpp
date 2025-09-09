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
void Emulator::hook_mem_read(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void* user_data) {
    uint64_t rip, rsp, gsbase;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_read(uc, UC_X86_REG_GS_BASE, &gsbase);  

    Emulator* self = static_cast<Emulator*>(user_data);


    if (address >= rsp && address < rsp + 0x1000)
        return;

    const uint64_t kuser_base = 0x00000007FFE0000;
    const uint64_t kuser_size = 0x1000;

    // KUSER_SHARED_DATA
    if (address >= kuser_base && address < kuser_base + kuser_size) {
        uint64_t offset = address - kuser_base;
        std::string description = "Unknown";

        auto it = kuser_shared_data_offsets.upper_bound(offset);
        if (it != kuser_shared_data_offsets.begin()) {
            --it;
            uint64_t base_offset = it->first;
            uint64_t delta = offset - base_offset;
            if (delta == 0)
                description = it->second;
            else
                description = it->second + " + 0x" + std::to_string(delta);
        }

        Logger::logf(Logger::Color::YELLOW,
            "[KUSER_SHARED_DATA] Reading (%s) [RIP: 0x%llx]",
            description.c_str(), rip);
        return;
    }

    // TEB
    if (address >= gsbase && address < gsbase + 0x1000) {
        uint64_t offset = address - gsbase;
        std::string description = "Unknown";

        auto it = teb_offsets.upper_bound(offset);
        if (it != teb_offsets.begin()) {
            --it;
            uint64_t base_offset = it->first;
            uint64_t delta = offset - base_offset;
            if (delta == 0)
                description = it->second;
            else
                description = it->second + " + 0x" + std::to_string(delta);
        }

        Logger::logf(Logger::Color::MAGENTA,
            "[TEB] Reading (%s) at 0x%llx [RIP: 0x%llx]",
            description.c_str(), address, rip);
        return;
    }

    // PEB (TEB + 0x60)
    uint64_t peb_address = 0;
    uc_mem_read(uc, gsbase + 0x60, &peb_address, sizeof(peb_address));
    if (address >= peb_address && address < peb_address + 0x1000) {
        uint64_t offset = address - peb_address;
        std::string description = "Unknown";

        auto it = peb_offsets.upper_bound(offset);
        if (it != peb_offsets.begin()) {
            --it;
            uint64_t base_offset = it->first;
            uint64_t delta = offset - base_offset;
            if (delta == 0)
                description = it->second;
            else
                description = it->second + " + 0x" + std::to_string(delta);
        }

        Logger::logf(Logger::Color::CYAN,
            "[PEB] Reading (%s) at 0x%llx [RIP: 0x%llx]",
            description.c_str(), address, rip);
        return;
    }
  
        if (self->loader.GetModuleNameByAddress(address) == self->wExeName) {
            Logger::logf(Logger::Color::GREEN,
                "[SELF-READ] Reading from code memory at 0x%llx [RIP: 0x%llx]",
                address, rip);
            return;
        }
    

}




void Emulator::hook_mem_write(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
        uint64_t rip, rsp;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        Emulator* self = static_cast<Emulator*>(user_data);


        if (address >= rsp && address < rsp + 0x1000) {
            return;
        }

        if (self->loader.GetModuleNameByAddress(address) == self->wExeName) {
            Logger::logf(Logger::Color::GREEN,
                "[SELF-Write] Writing in code memory at 0x%llx [RIP: 0x%llx]",
                address, rip);
            return;
        }
  //  Logger::logf(Logger::Color::YELLOW, "[MEM-WRITE] Address: 0x%llx  ", rip);
}


void Emulator::hook_cpuid(uc_engine* uc, void* user_data) {
    uint64_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    Logger::logf(Logger::Color::MAGENTA, "[CPUID] Executed at 0x%llx", rip);
}


void Emulator::hook_syscall(uc_engine* uc, void* user_data) {
    uint64_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uint64_t rax;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    Logger::logf(Logger::Color::CYAN, "[in Line SYSCALL]sycall : 0x%llx Executed at 0x%llx", rax, rip);
    Emulator* self = static_cast<Emulator*>(user_data);
    self->ReloadAtAddress(rip + 0x2);
    
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

    std::wstring moduleName = self->loader.GetModuleNameByAddress(address);
    if (moduleName != self->wExeName) {

    std::string funcName = self->loader.GetExportedFunctionNameByAddress(address);

    uint64_t return_address = self->Poi(UC_X86_REG_RSP);



    if (!funcName.empty()) {
        if (self->lastReloadedAddress != return_address) {
            Logger::logf(Logger::Color::CYAN, "[+] %s in %ls", funcName.c_str(), moduleName.c_str());
            self->lastReloadedAddress = return_address;
            self->ReloadAtAddress(return_address);
        }
    }


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

    uc_err err;

         err = uc_hook_add(unicorn, &trace_hook_block, UC_HOOK_BLOCK, (void*)hook_code_block, this, 1,0 );
        if (err != UC_ERR_OK) {
            Logger::logf(Logger::Color::RED, "[-] Failed to add code BLOCK hook : %s", uc_strerror(err));
            return false;
    
        }


    // uc_hook trace_hook;

   //   err = uc_hook_add(unicorn, &trace_hook, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);

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

    uc_hook mem_write_hook;
    err = uc_hook_add(unicorn, &mem_write_hook, UC_HOOK_MEM_WRITE, (void*)hook_mem_write, this, 1, 0);
    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] Failed to add memory write hook: %s", uc_strerror(err));
    }

    uc_hook cpuid_hook;
    uc_hook_add(unicorn, &cpuid_hook, UC_HOOK_INSN, hook_cpuid, this, 1, 0,
        UC_X86_INS_CPUID);


    // SYSCALL instruction
    uc_hook syscall_hook;
    uc_hook_add(unicorn, &syscall_hook, UC_HOOK_INSN, hook_syscall, this, 1, 0,
        UC_X86_INS_SYSCALL);



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
