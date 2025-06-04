#include "../headers/SimulatedDispatcher.h"
#include "../SimulatedWindows/kernel32/Kernel32Sim.h"
#include "../headers/DllEnum.h"

bool CallSimulatedFunction(const std::string& dllName, const std::string& functionName) {
    DllId dllId = GetDllIdFromString(dllName);

    switch (dllId) {
    case DllId::Kernel32:
        if (functionName == "GetSystemTimeAsFileTime") {
            Kernel32Sim::GetSystemTimeAsFileTime();
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