#include "../headers/SimulatedDispatcher.h"
#include "../SimulatedWindows/kernel32/Kernel32Sim.h"
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

        break;

    case DllId::User32:

        break;

    case DllId::Gdi32:

        break;

    default:
        break;
    }

    return false;
}