#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <iostream>

class Disassembler {
public:
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
        uint8_t code[16];
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
         //   std::cout << "[+] Disassembly at RIP:\n";
            std::cout << "0x" << std::hex << insn[0].address << ": "
                << insn[0].mnemonic << " " << insn[0].op_str << "\n";
            cs_free(insn, count);
        }
        else {
            std::cerr << "[!] Failed to disassemble at RIP\n";
        }

        cs_close(&cs);
    }
};
