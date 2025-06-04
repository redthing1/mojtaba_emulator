#include "Kernel32Sim.h"
#include <chrono>
#include <ctime>
#include "../../src/Logger.cpp"
#include <windows.h>

void Kernel32Sim::GetSystemTimeAsFileTime_s(Emulator& emu) {

	FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
	uint64_t Time_64 = *reinterpret_cast<uint64_t*>(&ft);
	uint32_t Time_32;
	std::memcpy(&Time_32, &ft, 4);
	uc_reg_write(emu.get_uc(), UC_X86_REG_RAX, &Time_32);
	uint64_t rcx = 0 ;
	uc_reg_read(emu.get_uc(), UC_X86_REG_RCX, &rcx);
	uc_mem_write(emu.get_uc(), rcx, &Time_64,sizeof(Time_64));
	uc_mem_read(emu.get_uc(), rcx, &Time_64, sizeof(Time_64));
	Logger::logf(Logger::Color::YELLOW, "[+] time was : 0x%llx", Time_64);

}
