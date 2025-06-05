#pragma once
#include <windows.h>
#include "../../headers/Emulator.hpp"
class Kernel32Sim {
public:
    static void GetSystemTimeAsFileTime_s(Emulator& emu);
    static void GetCurrentThreadId_s(Emulator& emu);
    static void GetCurrentProcessId_s(Emulator& emu);
    static void GetConsoleWindow_s(Emulator& emu);
    static void QueryPerformanceCounter_s(Emulator& emu);
    
};
