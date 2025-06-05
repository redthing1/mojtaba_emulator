#include "ucrtbase32Sim.hpp"
#include <chrono>
#include <ctime>
#include "../../src/Logger.cpp"


void ucrtbase32Sim::__stdio_common_vswprintf_s_s(Emulator& emu) {

	MessageBox(nullptr, "TLS Callback", "", 0);

}
