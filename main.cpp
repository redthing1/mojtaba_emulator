#include "./headers/Emulator.hpp"
#include "src/Logger.cpp"

int main() {
    Logger::logf(Logger::Color::GREEN, "[+] Starting Emulator...");

    std::string exepath = "D:\\Project\\emulator\\binary\\";
    std::string exeName = "SB-Win64-Shipping.exe";
    Emulator emulator(exepath, exeName);

    if (!emulator.initialize()) {
        Logger::logf(Logger::Color::RED, "[-] Emulator initialization failed.");
        return -1;
    }

    if (!emulator.start()) {
        Logger::logf(Logger::Color::RED, "[-] Emulation failed.");
        return -1;
    }

    return 0;
}
