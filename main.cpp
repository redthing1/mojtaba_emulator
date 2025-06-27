#include "./headers/Emulator.hpp"
#include "src/Logger.cpp"
#include <filesystem>

void printHelp() {
    Logger::logf(Logger::Color::GREEN, "Usage:");
    Logger::logf(Logger::Color::GREEN, "  emulator <full_path_to_exe>");
    Logger::logf(Logger::Color::GREEN, "\nExample:");
    Logger::logf(Logger::Color::GREEN, R"(  emulator "D:\helloworld.exe")");
    Logger::logf(Logger::Color::GREEN, "\nThis program runs the emulator on the specified executable.");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        Logger::logf(Logger::Color::RED, "[-] No executable path provided.");
        printHelp();
        return -1;
    }

    std::string arg1 = argv[1];
    if (arg1 == "-h" || arg1 == "--help") {
        printHelp();
        return 0;
    }

    std::string fullPath = arg1;
    std::filesystem::path path(fullPath);

    if (!std::filesystem::exists(path)) {
        Logger::logf(Logger::Color::RED, "[-] The specified executable does not exist:");
        Logger::logf(Logger::Color::RED, fullPath.c_str());
        return -1;
    }

    std::string exepath = path.parent_path().string();
    if (!exepath.empty() && exepath.back() != '\\' && exepath.back() != '/')
        exepath += "\\";

    std::string exeName = path.filename().string();

    Logger::logf(Logger::Color::GREEN, "[+] Starting Emulator...");
    Logger::logf(Logger::Color::GREEN, ("    Executable path: " + exepath).c_str());
    Logger::logf(Logger::Color::GREEN, ("    Executable name: " + exeName).c_str());

    Emulator emulator(exepath, exeName);

    if (!emulator.initialize()) {
        Logger::logf(Logger::Color::RED, "[-] Emulator initialization failed.");
        return -1;
    }

    if (!emulator.start()) {
        Logger::logf(Logger::Color::RED, "[-] Emulation failed.");
        return -1;
    }

    Logger::logf(Logger::Color::GREEN, "[+] Emulation finished successfully.");
    return 0;
}
