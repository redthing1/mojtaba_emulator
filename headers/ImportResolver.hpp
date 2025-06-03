#pragma once

#include <string>
#include <LIEF/PE.hpp>

class Emulator;  // <== forward declaration

class ImportResolver {
    class PELoader& loader;
    Emulator* emo;
    uc_engine* uc;

public:
    ImportResolver(uc_engine* unicorn, PELoader& pe_loader, Emulator* emulator);
    void resolve_imports(const LIEF::PE::Binary& binary, std::string name);
    void resolve_imports_For_dlls(const LIEF::PE::Binary& binary, const std::string& name);
    std::string function_name_resoler(const std::string& dll_name, uint64_t rva);
};
