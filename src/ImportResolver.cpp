#include <LIEF/PE.hpp>
#include <unicorn/unicorn.h>
#include <iostream>
#include "PELoader.cpp"
#include "Emulator.cpp"

class ImportResolver {
    PELoader& loader;
    uc_engine* uc;
    Emulator* emo;

public:

    ImportResolver(uc_engine* unicorn, PELoader& pe_loader, Emulator* emulator)
        : uc(unicorn), loader(pe_loader), emo(emulator) {
    }
  
    void resolve_imports(const LIEF::PE::Binary& binary, std::string name) {
        for (LIEF::PE::Import& import : binary.imports()) {
            std::string dll_name = import.name();


            if (loader.parsed_modules.find(dll_name) == loader.parsed_modules.end() ||
                loader.loaded_modules.find(dll_name) == loader.loaded_modules.end()) {

                std::string full_path = "D:\\Project\\emulator\\Dlls\\" + dll_name;

                if (!std::filesystem::exists(full_path)) {
                  // std::cerr << "[!] DLL not found: " << dll_name << " — skipping FOR : "<< name <<"\n";
                    continue;
                }

                std::cout << "[*] Loading DLL: " << dll_name << " For :" << name << "\n";

                try {
                    auto dll = loader.load_pe_binary(full_path);
                    uint64_t dll_base =  emo->reserve_memory( dll->optional_header().sizeof_image());
                    emo->map_pe_binary( *dll, dll_base, dll_name);
                    loader.loaded_modules[dll_name] = dll_base;
                    loader.add_to_parsed_moudal(dll_name,std::move(dll));
                    std::cout << "[+] Loaded DLL at: 0x" << std::hex << dll_base << "\n";
                }
                catch (...) {
                    std::cerr << "[!] Failed to load DLL: " << dll_name << "\n";
                    continue;
                }
            }

            uint64_t dll_base = loader.loaded_modules[dll_name];

            for (const auto& func : import.entries()) {
                if (!func.is_ordinal()) {
                    std::string func_name = func.name();

                    for (const LIEF::Function& exported_func : loader.parsed_modules[dll_name]->exported_functions()) {
                        if (func_name == exported_func.name()) {
                            uint64_t resolved_addr = dll_base + exported_func.address();

                            if (uc_mem_write(this->uc, loader.loaded_modules[name] + func.iat_address(), &resolved_addr, sizeof(resolved_addr)) != UC_ERR_OK) {
                                std::cerr << "[!] Failed to patch IAT at 0x" << std::hex << func.iat_address() << "\n";
                            }
                            else {
                                //  std::cout << "[+] Resolved import: " << func_name << " => 0x" << std::hex << resolved_addr << "\n";
                            }
                        }
                    }
                }
            }
        }
    }
    std::string get_exported_function_name(const std::string& dll_name, uint64_t address) {

        for (auto export_func : loader.parsed_modules[dll_name]->exported_functions()) {
            std::cout << "Name : " << export_func.name();
        }
        return "";
    }

    std::string function_name_resoler(const std::string& dll_name, uint64_t rva) {


            for (const auto& func : loader.parsed_modules[dll_name]->exported_functions()) {
                if (func.address() == rva) {
                    return func.name();
                }
            
        }
        return "";
    }
    void resolve_imports_For_dlls( const LIEF::PE::Binary& binary, const std::string& name) {
        for (const LIEF::PE::Import& import : binary.imports()) {
            const std::string& dll_name = import.name();

            if (loader.parsed_modules.find(dll_name) != loader.parsed_modules.end()) {
                resolve_imports(*loader.parsed_modules[dll_name], dll_name);
            }
            else {
                std::cerr << "[!] DLL not parsed yet: " << dll_name << " — skipping resolve\n";
            }
        }

    }
};
