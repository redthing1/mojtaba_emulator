#include "Kernel32Sim.hpp"
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


}
void Kernel32Sim::GetCurrentThreadId_s(Emulator& emu) {

	DWORD threadId32 = GetCurrentThreadId();                   // 32-bit
	uint64_t threadId64 = static_cast<uint64_t>(threadId32);   
	uc_reg_write(emu.get_uc(), UC_X86_REG_RAX, &threadId64);

}
void Kernel32Sim::GetCurrentProcessId_s(Emulator& emu) {

	DWORD threadId32 = GetCurrentProcessId();                   // 32-bit
	uint64_t threadId64 = static_cast<uint64_t>(threadId32);
	uc_reg_write(emu.get_uc(), UC_X86_REG_RAX, &threadId64);

}
void Kernel32Sim::QueryPerformanceCounter_s(Emulator& emu) {
	LARGE_INTEGER counter;
	if (QueryPerformanceCounter(&counter)) {
		uint64_t value = static_cast<uint64_t>(counter.QuadPart);
		uc_reg_write(emu.get_uc(), UC_X86_REG_RAX, &value);
	}
	else {
		uint64_t errorValue = 0;
		uc_reg_write(emu.get_uc(), UC_X86_REG_RAX, &errorValue);
	}
}
