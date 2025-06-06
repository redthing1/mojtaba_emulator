#pragma once

#include <string>
#include <LIEF/PE.hpp>

class Emulator;  // <== forward declaration

class ImportResolver {
     std::unordered_map<std::string, std::string> api_set_redirects = {
    {"api-ms-win-crt-", "ucrtbase.dll"},
    {"api-ms-win-core-processthreads", "kernel32.dll"},
    {"api-ms-win-core-", "kernelbase.dll"},
    {"api-ms-win-eventing-", "msvcp_win.dll" },
    {"api-ms-win-crt-stdio-", "ucrtbase.dll" },
    {"api-ms-win-security-", "win32u.dll" },
    {"api-ms-win-crt-runtime-", "win32u.dll" },
    {"api-ms-win-stateseparation-", "gdi32full.dll" }
    };
    class PELoader& loader;
    Emulator* emo;
    uc_engine* uc;
	std::string dll_path;

public:
    ImportResolver(uc_engine* unicorn, PELoader& pe_loader, Emulator* emulator,std::string dll_path);
    void resolve_imports(const LIEF::PE::Binary& binary, std::string name);
    void resolve_imports_For_dlls(const LIEF::PE::Binary& binary, const std::string& name);
    std::string function_name_resoler(const std::string& dll_name, uint64_t rva);
};
