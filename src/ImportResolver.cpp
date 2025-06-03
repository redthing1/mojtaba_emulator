#include "../headers/PELoader.hpp"
#include "../headers/Emulator.hpp"
#include "../headers/ImportResolver.hpp"
#include "logger.cpp"

    ImportResolver::ImportResolver(uc_engine* unicorn, PELoader& pe_loader, Emulator* emulator)
        : uc(unicorn), loader(pe_loader), emo(emulator) {
    }
  
    void ImportResolver::resolve_imports(const LIEF::PE::Binary& binary, std::string name) {
        for (LIEF::PE::Import& import : binary.imports()) {
            std::string dll_name = import.name();

            if (loader.parsed_modules.find(dll_name) == loader.parsed_modules.end() ||
                loader.loaded_modules.find(dll_name) == loader.loaded_modules.end()) {

                std::string full_path = "D:\\Project\\emulator\\Dlls\\" + dll_name;

                if (!std::filesystem::exists(full_path)) {
                 //   Logger::logf(Logger::Color::RED, "[!] DLL not found: %s — skipping (for: %s)", dll_name.c_str(), name.c_str());
                    continue;
                }

                Logger::logf(Logger::Color::GRAY, "[*] Loading DLL: %s (for: %s)", dll_name.c_str(), name.c_str());

                try {
                    auto dll = loader.load_pe_binary(full_path);
                    uint64_t dll_base = emo->reserve_memory(dll->optional_header().sizeof_image());
                    emo->map_pe_binary(*dll, dll_base, dll_name);
                    loader.loaded_modules[dll_name] = dll_base;
                    loader.add_to_parsed_moudal(dll_name, std::move(dll));
                    Logger::logf(Logger::Color::GRAY, "[+] Loaded DLL at: 0x%llx", dll_base);
                }
                catch (...) {
                    Logger::logf(Logger::Color::RED, "[!] Failed to load DLL: %s", dll_name.c_str());
                    continue;
                }
            }

            uint64_t dll_base = loader.loaded_modules[dll_name];
            const auto& export_object = loader.parsed_modules[dll_name]->get_export();

            for (const auto& func : import.entries()) {
                uint64_t resolved_addr = 0;

                if (!func.is_ordinal()) {
                    std::string func_name = func.name();

                    for (const LIEF::Function& exported_func : loader.parsed_modules[dll_name]->exported_functions()) {
                        if (func_name == exported_func.name()) {
                            resolved_addr = dll_base + exported_func.address();
                            Logger::logf(Logger::Color::GRAY, "[+] Resolved import: %s => 0x%llx", func_name.c_str(), resolved_addr);
                            break;
                        }
                    }

                    if (resolved_addr == 0) {
                        Logger::logf(Logger::Color::RED, "[!] Failed to resolve import: %s", func_name.c_str());
                        continue;
                    }

                }
                else {
                    uint16_t ordinal = static_cast<uint16_t>(func.data());

                    for (const auto& export_entry : export_object->entries()) {
                        if (export_entry.ordinal() == ordinal) {
                            resolved_addr = dll_base + export_entry.address();
                            Logger::logf(Logger::Color::YELLOW, "[+] Resolved ordinal import #%d => 0x%llx", ordinal, resolved_addr);
                            break;
                        }
                    }

                    if (resolved_addr == 0) {
                        Logger::logf(Logger::Color::RED, "[!] Failed to resolve ordinal import #%d", ordinal);
                        continue;
                    }
                }

                // patch IAT
                if (uc_mem_write(this->uc,
                    loader.loaded_modules[name] + func.iat_address(),
                    &resolved_addr,
                    sizeof(resolved_addr)) != UC_ERR_OK) {
                    Logger::logf(Logger::Color::RED, "[!] Failed to patch IAT at 0x%llx", func.iat_address());
                }
            }
        }
    }

    std::string  ImportResolver::function_name_resoler(const std::string& dll_name, uint64_t rva) {

            for (const auto& func : loader.parsed_modules[dll_name]->exported_functions()) {
                if (func.address() == rva) {
                    return func.name();
                }
            
        }
           
        return dll_name + " + 0x" + std::to_string(rva);

    }
    void  ImportResolver::resolve_imports_For_dlls( const LIEF::PE::Binary& binary, const std::string& name) {
        for (const LIEF::PE::Import& import : binary.imports()) {
            const std::string& dll_name = import.name();

            if (loader.parsed_modules.find(dll_name) != loader.parsed_modules.end()) {
                resolve_imports(*loader.parsed_modules[dll_name], dll_name);
            }
            else {
                Logger::logf(Logger::Color::RED, "[!] DLL not parsed yet: %s — skipping resolve", dll_name.c_str());
            }
        }

    }

