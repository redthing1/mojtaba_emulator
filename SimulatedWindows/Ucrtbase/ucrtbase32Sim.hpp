#pragma once
#include <windows.h>
#include "../../headers/Emulator.hpp"
class ucrtbase32Sim {
public:
    static void __stdio_common_vswprintf_s_s(Emulator& emu);
    static void _initterm_e_s(Emulator& emu);
};
