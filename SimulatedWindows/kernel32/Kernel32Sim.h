#pragma once
#include <windows.h>
#include "../../headers/Emulator.hpp"
class Kernel32Sim {
public:
    static void GetSystemTimeAsFileTime_s(Emulator& emu);
};
