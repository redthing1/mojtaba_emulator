#include "../headers/Emulator.hpp"
#include "../headers/ImportResolver.hpp"
#include "logger.cpp"

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

void Emulator::map_kuser_shared_data() {
    uc_mem_map(uc, KUSER_SHARED_DATA_ADDRESS, KUSER_SHARED_DATA_SIZE, UC_PROT_READ);
    void* shared_data = reinterpret_cast<void*>(KUSER_SHARED_DATA_ADDRESS);
    uc_mem_write(uc, KUSER_SHARED_DATA_ADDRESS, shared_data, KUSER_SHARED_DATA_SIZE);
}

void Emulator::setup_hooks(void* context) {
    uc_hook trace;
    Logger::logf(Logger::Color::GREEN, "[*] Adding code hook... ");
    uc_err err = uc_hook_add(get_uc(), &trace, UC_HOOK_BLOCK, code_hook_cb, context, main_code_end, next_free_address);
    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED, "[-] uc_hook_add failed: %s", uc_strerror(err));
    }
    else {
        Logger::logf(Logger::Color::GREEN, "[+] Hook added successfully", uc_strerror(err));
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

    Logger::logf(Logger::Color::YELLOW, "[+] %s Called.", resolver->function_name_resoler(dllname, Dll_rva).c_str());
    //emu->emu_ret();
}
