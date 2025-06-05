#include "user32Sim.hpp"
#include <chrono>
#include <ctime>
#include "../../src/Logger.cpp"


 void user32Sim::MessageBoxW_s(Emulator& emu) {

	 HWND hWnd;
	 uc_reg_read(emu.get_uc(), UC_X86_REG_RCX, &hWnd);


	 uint64_t rdx;
	 uc_reg_read(emu.get_uc(), UC_X86_REG_RDX, &rdx);

	 uint64_t r8;
	 uc_reg_read(emu.get_uc(), UC_X86_REG_R8, &r8);

	 wchar_t lpText[512];
	 uc_mem_read(emu.get_uc(), rdx , lpText, sizeof(lpText));


	 wchar_t lpCaption[512];
	 uc_mem_read(emu.get_uc(), r8, lpCaption, sizeof(lpCaption));

	 uint64_t r9;
	 uc_reg_read(emu.get_uc(), UC_X86_REG_R9, &r9);

	 UINT uType = static_cast<UINT>(r9); 

	 MessageBoxW(hWnd, lpText, lpCaption, uType);

}
