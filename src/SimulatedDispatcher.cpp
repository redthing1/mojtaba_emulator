#include "../headers/SimulatedDispatcher.hpp"
#include "../SimulatedWindows/kernel32/Kernel32Sim.hpp"
#include "../SimulatedWindows/user32/user32Sim.hpp"
#include "../SimulatedWindows/Ucrtbase/ucrtbase32Sim.hpp"
#include "../headers/DllEnum.h"

bool CallSimulatedFunction(const std::string& dllName, const std::string& functionName, Emulator& emu) {
    DllId dllId = GetDllIdFromString(dllName);

    switch (dllId) {
    case DllId::Kernel32:
        if (functionName == "GetSystemTimeAsFileTime") {
            Kernel32Sim::GetSystemTimeAsFileTime_s(emu);
            return true;
        }
        if (functionName == "GetCurrentThreadId") {
            Kernel32Sim::GetCurrentThreadId_s(emu);
            return true;
        }
        if (functionName == "GetCurrentProcessId") {
            Kernel32Sim::GetCurrentProcessId_s(emu);
            return true;
		}
        if (functionName == "QueryPerformanceCounter") {
            Kernel32Sim::QueryPerformanceCounter_s(emu);
            return true;
		}
        if (functionName == "GetConsoleWindow") {
            Kernel32Sim::GetConsoleWindow_s(emu);
            return true;
        }
        
        break;

    case DllId::User32:
        if (functionName == "MessageBoxW") {
            user32Sim::MessageBoxW_s(emu);
            return true;
        }
        break;
    case DllId::Ucrtbase:
        if (functionName == "__stdio_common_vswprintf_s") {
            ucrtbase32Sim::__stdio_common_vswprintf_s_s(emu);
            return true;
        }
        break;
    case DllId::Gdi32:

        break;

    default:
        break;
    }

    return false;
}