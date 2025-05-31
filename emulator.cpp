#include <LIEF/PE.hpp>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <memory>
#include <iostream>

#define STACK_ADDRESS 0x2000000
#define STACK_SIZE (2 * 1024 * 1024)
#define PAGE_SIZE 0x1000

size_t align_up(size_t size, size_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}



void print_registers(uc_engine* uc) {
    struct {
        uc_x86_reg reg;
        const char* name;
    } regs[] = {
        {UC_X86_REG_RIP, "RIP"}, {UC_X86_REG_RSP, "RSP"},
        {UC_X86_REG_RAX, "RAX"}, {UC_X86_REG_RBX, "RBX"},
        {UC_X86_REG_RCX, "RCX"}, {UC_X86_REG_RDX, "RDX"},
        {UC_X86_REG_RSI, "RSI"}, {UC_X86_REG_RDI, "RDI"},
        {UC_X86_REG_RBP, "RBP"}, {UC_X86_REG_R8,  "R8"},
        {UC_X86_REG_R9,  "R9"},  {UC_X86_REG_R10, "R10"},
        {UC_X86_REG_R11, "R11"}, {UC_X86_REG_R12, "R12"},
        {UC_X86_REG_R13, "R13"}, {UC_X86_REG_R14, "R14"},
        {UC_X86_REG_R15, "R15"},
    };

    for (auto& r : regs) {
        uint64_t val;
        uc_reg_read(uc, r.reg, &val);
        std::cout << r.name << ": 0x" << std::hex << val << "\n";
    }
}

void disassemble_at(uc_engine* uc, uint64_t rip) {
    uint8_t code[16];  // حداکثر طول یک دستور x86_64
    if (uc_mem_read(uc, rip, code, sizeof(code)) != UC_ERR_OK) {
        std::cerr << "[!] Cannot read memory for disassembly\n";
        return;
    }

    csh cs;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) {
        std::cerr << "[!] Failed to initialize Capstone\n";
        return;
    }

    count = cs_disasm(cs, code, sizeof(code), rip, 1, &insn);
    if (count > 0) {
        std::cout << "[+] Disassembly at RIP:\n";
        std::cout << "0x" << std::hex << insn[0].address << ": "
            << insn[0].mnemonic << " " << insn[0].op_str << "\n";
        cs_free(insn, count);
    }
    else {
        std::cerr << "[!] Failed to disassemble at RIP\n";
    }
    cs_close(&cs);
}

void instruction_hook(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    disassemble_at(uc, address);
    print_registers(uc);
    }

int main() {
    auto pe = LIEF::PE::Parser::parse("D:\\Project\\emulator\\binary\\helloworld.exe");
    if (!pe) return 1;

    uint64_t image_base = pe->optional_header().imagebase();
    uint64_t entry_point = pe->entrypoint();

    uc_engine* uc;
    if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) return 1;

    for (const auto& section : pe->sections()) {
        if (section.virtual_size() == 0) continue;
        uint64_t vaddr = image_base + section.virtual_address();
        size_t mem_size = align_up((((section.virtual_size()) > (section.size())) ? (section.virtual_size()) : (section.size())), PAGE_SIZE);
        uc_mem_map(uc, vaddr, mem_size, UC_PROT_ALL);
        if (!section.content().empty()) {
            uc_mem_write(uc, vaddr, section.content().data(), section.content().size());
        }
    }

    uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
    uint64_t rsp = STACK_ADDRESS + STACK_SIZE - 0x100;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_write(uc, UC_X86_REG_RIP, &entry_point);

    std::cout << "[+] Emulation started\n";

 // Print all instructions!
 //   uc_hook trace;
 //   uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)instruction_hook, nullptr, 1, 0);

    auto err = uc_emu_start(uc, entry_point, 0, 0, 0);
    if (err != UC_ERR_OK) {
        uint64_t rip = 0;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        std::cerr << "[!] Emulation error at 0x" << std::hex << rip << "\n";
        std::cerr << "[!] Error: " << uc_strerror(err) << "\n";

        print_registers(uc);
        disassemble_at(uc, rip);
    }

    uc_close(uc);
    std::cout << "[+] Emulation ENDED!" << '\n';
    getchar();
    return 0;
}
