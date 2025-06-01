#pragma once
#include <unicorn/unicorn.h>
#include <iostream>
#include <LIEF/PE.hpp>

#define STACK_ADDRESS 0x2000000
#define STACK_SIZE (2 * 1024 * 1024)
#define PAGE_SIZE 0x1000
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000

class Emulator {
    uc_engine* uc;
    uint64_t next_free_address = 0x150000000;

public:
    Emulator() {
        if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) {
            std::cerr << "[!] Failed to initialize Unicorn\n";
            exit(1);
        }
    }

    ~Emulator() {
        if (uc) {
            uc_close(uc);
        }
    }

    uc_engine* get_uc() const { return uc; }

    size_t align_up(size_t size, size_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

    uint64_t reserve_memory(size_t size, int perms = UC_PROT_ALL) {
        size = align_up(size, PAGE_SIZE);
        uint64_t addr = this->next_free_address;
        if (uc_mem_map(this->uc, addr, size, perms) != UC_ERR_OK) {
            std::cerr << "[!] Failed to reserve memory at 0x" << std::hex << addr << "\n";
            exit(1);
        }
        this->next_free_address += size;
        return addr;
    }


    void map_pe_binary(const LIEF::PE::Binary& binary, uint64_t load_base = 0) {
        uint64_t image_base = load_base ? load_base : next_free_address;

        size_t total_size = align_up(binary.optional_header().sizeof_image(), PAGE_SIZE);
        uc_mem_map(this->uc, image_base, total_size, UC_PROT_ALL);

        //std::cout << "[+] Maping : " <<  <<"\n";

        if (!load_base) {
            next_free_address += total_size;
        }
        else {
            // اگر بارگذاری دستی آدرس دادید، next_free_address را به بعد این محدوده ببرید
            if (next_free_address < image_base + total_size) {
                next_free_address = image_base + total_size;
            }
        }

        for (const auto& section : binary.sections()) {
            if (section.virtual_size() == 0) continue;

            uint64_t virt_addr = image_base + section.virtual_address();
            size_t virt_size = align_up(max(section.virtual_size(), section.size()), PAGE_SIZE);

            uc_mem_map(this->uc, virt_addr, virt_size, UC_PROT_ALL);
            if (!section.content().empty()) {
                uc_mem_write(this->uc, virt_addr, section.content().data(), section.content().size());
            }

            std::cout << "[+] Mapped section " << section.name()
                << " at 0x" << std::hex << virt_addr << " (size: " << virt_size << ")\n";
        }
    }



    void setup_stack() {
        uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
        uint64_t rsp = STACK_ADDRESS + STACK_SIZE - 0x10000;
        uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    }

    void map_kuser_shared_data() {
        uc_mem_map(uc, KUSER_SHARED_DATA_ADDRESS, KUSER_SHARED_DATA_SIZE, UC_PROT_READ);
        void* shared_data = reinterpret_cast<void*>(KUSER_SHARED_DATA_ADDRESS);
        uc_mem_write(uc, KUSER_SHARED_DATA_ADDRESS, shared_data, KUSER_SHARED_DATA_SIZE);
    }

    void setup_hooks(uc_engine* hook_cb) {
        uc_hook trace;
        uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_cb, nullptr, 1, 0);
    }

    void set_entry_point(uint64_t entry_point) {
        uc_reg_write(uc, UC_X86_REG_RIP, &entry_point);
    }

    void start_emulation(uint64_t start_addr) {
        auto err = uc_emu_start(uc, start_addr, 0, 0, 0);
        if (err != UC_ERR_OK) {
            uint64_t rip = 0;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);
            std::cerr << "[!] Emulation error at 0x" << std::hex << rip << "\n";
            std::cerr << "[!] Error: " << uc_strerror(err) << "\n";
        }
    }
};
