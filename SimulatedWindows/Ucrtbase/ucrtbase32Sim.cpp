#include "ucrtbase32Sim.hpp"
#include <chrono>
#include <ctime>
#include "../../src/Logger.cpp"
#include <corecrt_startup.h>
//#include <corecrt_startup.h>


void ucrtbase32Sim::__stdio_common_vswprintf_s_s(Emulator& emu) {

    uint64_t options;
    uc_reg_read(emu.get_uc(), UC_X86_REG_RCX, &options);


    uint64_t Rdx;
    uc_reg_read(emu.get_uc(), UC_X86_REG_RDX, &Rdx);

    uint64_t Buffer_size;
    uc_reg_read(emu.get_uc(), UC_X86_REG_R8, &Buffer_size);


    uint64_t FormatPtr;
    uc_reg_read(emu.get_uc(), UC_X86_REG_R9, &FormatPtr);



    wchar_t formatBuffer[512] = { 0 };
    uc_mem_read(emu.get_uc(), FormatPtr, &formatBuffer, sizeof(formatBuffer));

    uint64_t Rsp;
    uc_reg_read(emu.get_uc(), UC_X86_REG_RSP, &Rsp);


    _locale_t Locale;
    uc_mem_read(emu.get_uc(), Rsp + 0x20, &Locale, sizeof(_locale_t));


    wchar_t ArgList[512];
    uc_mem_read(emu.get_uc(), Rsp + 0x28, ArgList,  sizeof(ArgList));


    std::vector<wchar_t> Buffer(Buffer_size);
    memset(Buffer.data(), 0, Buffer_size * sizeof(wchar_t));



    int result = __stdio_common_vswprintf_s(
        options,
        Buffer.data(),
        Buffer_size,
        formatBuffer,
        Locale,
        (va_list)ArgList
    );

    if (result < 0) {
        Logger::logf(Logger::Color::RED, "[-] __stdio_common_vswprintf_s failed! Return value: %d", result);
    }

    uc_mem_write(emu.get_uc(), Rdx, Buffer.data(), Buffer_size * sizeof(wchar_t));

}

void ucrtbase32Sim::_initterm_e_s(Emulator& emu) {
	uint64_t Rcx;
	uc_reg_read(emu.get_uc(), UC_X86_REG_RCX, &Rcx);


	uint64_t Rdx;
	uc_reg_read(emu.get_uc(), UC_X86_REG_RDX, &Rdx);

    X86RegisterState snapshot = emu.save_registers(emu.get_uc());

    uint64_t fnuction_addr;
    while (Rcx < Rdx) {

        uc_mem_read(emu.get_uc(), Rcx, &fnuction_addr, sizeof(fnuction_addr));
        if (fnuction_addr == 0) {
            Logger::logf(Logger::Color::YELLOW, "[*] Reached end of function pointers at %p", Rcx);
            Rcx += 8;
            continue;
        }
        Logger::logf(Logger::Color::GREEN, "[+] Calling function at %p", fnuction_addr);
        // Call the function
		uc_reg_write(emu.get_uc(), UC_X86_REG_RIP, &fnuction_addr);
        auto err = uc_emu_start(emu.get_uc(), fnuction_addr, 0, 0, 0);
		// Move to the next function pointer

		Rcx += 8; // Move to the next function pointer
    }



    emu.restore_registers(emu.get_uc(), snapshot);
    uc_reg_write(emu.get_uc(), UC_X86_REG_RAX, 0);
}