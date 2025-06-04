#include "../headers/Emulator.hpp"
#include "../headers/ImportResolver.hpp"
#include "../headers/SimulatedDispatcher.h"
#include "logger.cpp"

#ifdef _M_X64
PNT_TIB GetTeb() {
    return (PNT_TIB)__readgsqword(0x30);
}
#endif

struct HookContext {
    Emulator* emulator;
    ImportResolver* resolver;
};

Emulator::Emulator() {
    if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) {
        std::cerr << "[!] Failed to initialize Unicorn\n";
        exit(1);
    }
}

Emulator::~Emulator() {
    if (uc) uc_close(uc);
}

uc_engine* Emulator::get_uc() const { return uc; }

size_t Emulator::align_up(size_t size, size_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

void Emulator::set_code_bounds(uint64_t start, uint64_t end, const std::string& binary_name) {
    main_code_start = start;
    main_code_end = end;
    main_binary_name = binary_name;
}

uint64_t Emulator::reserve_memory(size_t size, int perms) {
    size = align_up(size, PAGE_SIZE);
    uint64_t addr = next_free_address;
    if (uc_mem_map(uc, addr, size, perms) != UC_ERR_OK) {
        std::cerr << "[!] Failed to reserve memory at 0x" << std::hex << addr << "\n";
        exit(1);
    }
    next_free_address += size;
    return addr;
}
bool Emulator::isGsSegment(uint64_t addr) {
    return addr <= 0xFFFF;
}

void Emulator::map_pe_binary(const LIEF::PE::Binary& binary, uint64_t load_base, std::string name) {
    uint64_t image_base = load_base ? load_base : next_free_address;
    size_t total_size = align_up(binary.optional_header().sizeof_image(), PAGE_SIZE);
    uc_mem_map(uc, image_base, total_size, UC_PROT_ALL);

    if (!load_base) next_free_address += total_size;
    else if (next_free_address < image_base + total_size) next_free_address = image_base + total_size;

    for (const auto& section : binary.sections()) {
        if (section.virtual_size() == 0) continue;

        uint64_t virt_addr = image_base + section.virtual_address();
        size_t virt_size = align_up(max(section.virtual_size(), section.size()), PAGE_SIZE);

        uc_mem_map(uc, virt_addr, virt_size, UC_PROT_ALL);
        if (!section.content().empty()) {
            uc_mem_write(uc, virt_addr, section.content().data(), section.content().size());
        }
       // Logger::logf(Logger::Color::GRAY, "[+] Mapped section : %s at 0x%llx (size: %llx )", section.name().c_str(), virt_addr, virt_size);

    }

    loaded_binaries.push_back(BinaryInfo{ name, image_base, total_size });
}

void Emulator::setup_stack() {
    uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
    uint64_t rsp = STACK_ADDRESS + STACK_SIZE - 0x10000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
}
void Emulator::CopyTebPebToBuffer(uint8_t* tebBuf, size_t tebSize, uint8_t* pebBuf, size_t pebSize) {
#ifdef _M_X64
    PNT_TIB teb = (PNT_TIB)__readgsqword(0x30);
    void* peb = *(void**)((uint8_t*)teb + 0x60);

    memcpy(tebBuf, teb, min(tebSize, size_t(0x1000)));
    memcpy(pebBuf, peb, min(pebSize, size_t(0x1000)));
#endif
}
PVOID Emulator::GetPebFromTeb() {
    auto teb = GetTeb();
    return *(PVOID*)((BYTE*)teb + 0x60);  
}
void Emulator::setup_TEB_PEB() {

    uc_mem_map(uc, GS_BASE, 2 * 1024 * 1024, UC_PROT_ALL);

    const size_t tebSize = 0x1000;
    const size_t pebSize = 0x1000;

    uint8_t tebBuf[tebSize] = {};
    uint8_t pebBuf[pebSize] = {};


    CopyTebPebToBuffer(tebBuf, tebSize, pebBuf, pebSize);
    uc_mem_write(uc, 0x7FFDF0000000, tebBuf, tebSize);
    uc_mem_write(uc, 0x7FFDF0001000, pebBuf, pebSize);
}
void Emulator::map_kuser_shared_data() {
    uc_mem_map(uc, KUSER_SHARED_DATA_ADDRESS, KUSER_SHARED_DATA_SIZE, UC_PROT_READ);
    void* shared_data = reinterpret_cast<void*>(KUSER_SHARED_DATA_ADDRESS);
    uc_mem_write(uc, KUSER_SHARED_DATA_ADDRESS, shared_data, KUSER_SHARED_DATA_SIZE);
}

void Emulator::setup_hooks(void* context) {

    uc_hook trace;
    uc_hook trace_mem_read;
    uc_hook trace_mem_read_unmaped;

    Logger::logf(Logger::Color::GREEN, "[*] Adding code hook... ");

    is_hooked(uc_hook_add(uc, &trace, UC_HOOK_BLOCK, code_hook_cb, context, main_code_end, next_free_address), "CODE HOOK");
    is_hooked(uc_hook_add(uc, &trace_mem_read, UC_HOOK_MEM_READ, hook_mem_read, context, main_code_start, main_code_end), "hook_mem_read");
    is_hooked(uc_hook_add(uc, &trace_mem_read, UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read, context, main_code_start, main_code_end), "hook_mem_read_unMaped");

}
void Emulator::is_hooked(uc_err err ,std::string HookName) {

    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] %s failed: %s", HookName.c_str(), uc_strerror(err));
    }
    else {
        Logger::logf(Logger::Color::GREEN, "[+] %s added successfully", HookName.c_str());
    }
}
void Emulator::set_entry_point(uint64_t entry_point) {
    uc_reg_write(uc, UC_X86_REG_RIP, &entry_point);
}

BinaryInfo* Emulator::find_binary_by_address(uint64_t address) {
    for (auto& bin : loaded_binaries) {
        if (address >= bin.base && address < bin.base + bin.size)
            return &bin;
    }
    return nullptr;
}

void Emulator::emu_ret() {
    static const uint64_t ret_stub_addr = 0x1000;
    static bool is_stub_mapped = false;

    if (!is_stub_mapped) {
        uc_err err = uc_mem_map(uc, ret_stub_addr, 0x1000, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            Logger::logf(Logger::Color::RED, "[!] Failed to map memory for ret stub:  %s", uc_strerror(err));
            return;
        }

        uint8_t ret_instr = 0xC3;
        err = uc_mem_write(uc, ret_stub_addr, &ret_instr, 1);
        if (err != UC_ERR_OK) {
            Logger::logf(Logger::Color::RED, "[!] Failed to write ret instruction: %s", uc_strerror(err));
            return;
        }

        is_stub_mapped = true;
    }

    uc_reg_write(uc, UC_X86_REG_RIP, &ret_stub_addr);
}

std::string Emulator::get_function_name_from_pdb(const std::string& dll_path, uint64_t rva) {
    HANDLE hProcess = GetCurrentProcess();
    if (!SymInitialize(hProcess, NULL, FALSE)) return "";

    DWORD64 baseAddress = SymLoadModuleEx(hProcess, NULL, dll_path.c_str(), NULL, 0, 0, NULL, 0);
    if (baseAddress == 0) return "";

    uint64_t address = baseAddress + rva;
    BYTE buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;
    if (SymFromAddr(hProcess, address, &displacement, pSymbol)) {
        return std::string(pSymbol->Name);
    }
    else {
        Logger::logf(Logger::Color::RED, "SymFromAddr failed: %s", GetLastError());
        return "";
    }
}

void Emulator::start_emulation(uint64_t start_addr) {
    auto err = uc_emu_start(uc, start_addr, 0, 0, 0);
    if (err != UC_ERR_OK) {
        uint64_t rip = 0;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        Logger::logf(Logger::Color::RED, "[!] Emulation error at 0x%llx", rip);
        Logger::logf(Logger::Color::RED, "[!] Error: %s", uc_strerror(err));
    }
}

void Emulator::code_hook_cb(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    HookContext* ctx = static_cast<HookContext*>(user_data);
    Emulator* emu = ctx->emulator;
    ImportResolver* resolver = ctx->resolver;
    uint64_t rip;

    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    BinaryInfo* bin = emu->find_binary_by_address(address);

    auto& dllname = bin->name;
    auto Dll_rva = address - bin->base;
    std::string function_name =  resolver->function_name_resoler(dllname, Dll_rva);

    Logger::logf(Logger::Color::YELLOW, "[+] %s Called.", function_name.c_str());
    

    if (CallSimulatedFunction(dllname, function_name,*emu)) {
        emu->emu_ret();
    }
    else {
        Logger::logf(Logger::Color::RED, "[-] %s is unimplanted yet.", function_name.c_str());
    }


}
 bool Emulator::hook_mem_read(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void* user_data) {
    HookContext* ctx = static_cast<HookContext*>(user_data);
    Emulator* emu = ctx->emulator;
    ImportResolver* resolver = ctx->resolver;

    uint64_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);


    if (emu->isGsSegment(address)) {
        uint64_t real_addr = GS_BASE + address;

        uint8_t buf[16] = { 0 };
        if (size > (int)sizeof(buf)) {
            Logger::logf(Logger::Color::RED, "[-] Size too big in mem_read hook .");

            return false;
        }


        uc_err err = uc_mem_read(uc, real_addr, buf, size);
        if (err != UC_ERR_OK) {
            Logger::logf(Logger::Color::RED, "[-] Failed to read memory at GS base adjusted addr: 0x%llx ", real_addr);
            return false;
        }

        Logger::logf(Logger::Color::GREEN, "[+] Read from GS segment at offset 0x%llx form : 0x%llx", address, rip);

    }
    else {
    Logger::logf(Logger::Color::GREEN, "[+] Read from 0x%llx memory at 0x%llx ", address, rip);
    }
    return true;
}
 void Emulator::setup_tls(LIEF::PE::Binary &bin , uint64_t start_addr) {

     if (bin.has_tls()) {
         uint64_t address_of_tls = 0;  
         if (uc_mem_read(uc, bin.tls()->addressof_callbacks(), &address_of_tls, sizeof(address_of_tls)) == UC_ERR_OK) {

         uint64_t tls_callback_function_addr = start_addr + (address_of_tls - bin.imagebase());
         Logger::logf(Logger::Color::YELLOW, "[+] Program has Tls at 0x%llx  ", address_of_tls);
         
         set_entry_point(tls_callback_function_addr);
         start_emulation(tls_callback_function_addr);
         }

    }



 }

 bool Emulator::hook_mem_read_unmaped(uc_engine* uc, uc_mem_type type, uint64_t address,
     int size, int64_t value, void* user_data) {
     HookContext* ctx = static_cast<HookContext*>(user_data);
     Emulator* emu = ctx->emulator;
     ImportResolver* resolver = ctx->resolver;

     uint64_t rip;
     uc_reg_read(uc, UC_X86_REG_RIP, &rip);

     if (emu->isGsSegment(address)) {

         Logger::logf(Logger::Color::GREEN, "[+] Read from GS segment at offset 0x%llx form : 0x%llx it UnMaped ", address, rip);

     }
     else {
         Logger::logf(Logger::Color::GREEN, "[+] Read from 0x%llx memory at 0x%llx  it UnMaped", address, rip);
     }
     return true;
 }
