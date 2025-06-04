#include "user32Sim.hpp"
#include <chrono>
#include <ctime>
#include "../../src/Logger.cpp"


 void user32Sim::MessageBoxW_s(Emulator& emu) {

	MessageBox(nullptr, "TLS Callback", "", 0);

}
