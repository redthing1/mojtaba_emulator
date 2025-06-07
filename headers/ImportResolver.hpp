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
    bool load_dll_if_needed(const std::string& dll_name, const std::string& for_module);
    std::string resolve_library_name(const std::string& original_name);
    void log_needed_dlls(const LIEF::PE::Binary& binary, const std::string& name);
    uint64_t resolve_function_address(const LIEF::PE::ImportEntry& func,const std::string& dll_name,uint64_t dll_base);
    void resolve_imports_For_dlls(const LIEF::PE::Binary& binary, const std::string& name);
    void patch_iat_entry(const std::string& module_name, uint64_t iat_offset, uint64_t address);
    std::string function_name_resoler(const std::string& dll_name, uint64_t rva);
};
