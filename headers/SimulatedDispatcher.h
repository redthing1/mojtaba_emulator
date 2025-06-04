#pragma once
#include <string>
#include <windows.h>
#include "../headers/Emulator.hpp"

bool CallSimulatedFunction(const std::string& dllName, const std::string& functionName,Emulator& emu);
