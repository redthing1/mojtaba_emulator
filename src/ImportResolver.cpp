#include "../headers/PELoader.hpp"
#include "../headers/Emulator.hpp"
#include "../headers/ImportResolver.hpp"
#include "logger.cpp"

    ImportResolver::ImportResolver(uc_engine* unicorn, PELoader& pe_loader, Emulator* emulator,std::string dll_path)
        : uc(unicorn), loader(pe_loader), emo(emulator),dll_path(dll_path) {
    }

    void ImportResolver::resolve_imports(const LIEF::PE::Binary& binary, std::string name ) {


        for (const std::string& import : binary.imported_libraries()) {
            std::string display_name = import;
            for (const auto& [prefix, redirect] : api_set_redirects) {
                if (display_name.rfind(prefix, 0) == 0) {
                    display_name = redirect;
                    break;
                }
            }

            if (name == emo->main_binary_name) {
                Logger::logf(Logger::Color::GRAY, "[*] %s Need DLL: %s .", emo->main_binary_name.c_str(), display_name.c_str());
            }
        }

        for (const LIEF::PE::Import& import : binary.imports()) {
            std::string dll_name = import.name();
            for (const auto& [prefix, redirect] : api_set_redirects) {
                if (dll_name.rfind(prefix, 0) == 0) {
                    dll_name = redirect;
                    break;
                }
            }

            if (loader.parsed_modules.find(dll_name) == loader.parsed_modules.end() ||
                loader.loaded_modules.find(dll_name) == loader.loaded_modules.end()) {
                std::string full_path = "";
                if (dll_path.empty()) {
                  full_path = "C:\\Windows\\System32\\" + dll_name;
                }
                else {
                  full_path = dll_path + dll_name;
                }


                if (!std::filesystem::exists(full_path)) {
                    Logger::logf(Logger::Color::RED, "[!] DLL not found: %s — skipping (for: %s)", dll_name.c_str(), name.c_str());
                    continue;
                }

                Logger::logf(Logger::Color::GRAY, "[*] Loading DLL: %s (for: %s)", dll_name.c_str(), name.c_str());

                try {
                    auto dll = loader.load_pe_binary(full_path);
                    uint64_t dll_base = emo->reserve_memory(dll->optional_header().sizeof_image());
                    emo->map_pe_binary(*dll, dll_base, dll_name);
                    loader.loaded_modules[dll_name] = dll_base;
                    loader.add_to_parsed_moudal(dll_name, std::move(dll));
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
                            break;
                        }
                    }


                    if (resolved_addr == 0 && func_name.rfind("Rtl", 0) == 0) {
                        std::string fallback_dll = "ntdll.dll";

                        if (loader.loaded_modules.find(fallback_dll) == loader.loaded_modules.end()) {
                            std::string fallback_path = "D:\\Project\\emulator\\Dlls\\" + fallback_dll;

                            if (std::filesystem::exists(fallback_path)) {
                                auto dll = loader.load_pe_binary(fallback_path);
                                uint64_t dll_base = emo->reserve_memory(dll->optional_header().sizeof_image());
                                emo->map_pe_binary(*dll, dll_base, fallback_dll);
                                loader.loaded_modules[fallback_dll] = dll_base;
                                loader.add_to_parsed_moudal(fallback_dll, std::move(dll));
                            }
                        }

                        uint64_t ntdll_base = loader.loaded_modules[fallback_dll];
                        const auto& fallback_exports = loader.parsed_modules[fallback_dll]->exported_functions();
                        for (const auto& exported_func : fallback_exports) {
                            if (func_name == exported_func.name()) {
                                resolved_addr = ntdll_base + exported_func.address();
                                break;
                            }
                        }
                    }


                    if (resolved_addr == 0) {
                        for (const auto& [mod_name, mod_base] : loader.loaded_modules) {
                            const auto& mod_exports = loader.parsed_modules[mod_name]->exported_functions();
                            for (const auto& exported_func : mod_exports) {
                                if (func_name == exported_func.name()) {
                                    resolved_addr = mod_base + exported_func.address();
                                   // Logger::logf(Logger::Color::YELLOW, "[~] Fallback resolved: %s from %s", func_name.c_str(), mod_name.c_str());
                                    break;
                                }
                            }
                            if (resolved_addr != 0) break;
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
                            break;
                        }
                    }

                    if (resolved_addr == 0) {
                        Logger::logf(Logger::Color::RED, "[!] Failed to resolve ordinal import #%d", ordinal);
                        continue;
                    }
                }

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
           
        return NULL;

    }
    void  ImportResolver::resolve_imports_For_dlls( const LIEF::PE::Binary& binary, const std::string& name) {
        for (const LIEF::PE::Import& import : binary.imports()) {
             std::string dll_name = import.name();

            for (const auto& [prefix, redirect] : api_set_redirects) {
                if (dll_name.rfind(prefix, 0) == 0) {
                    dll_name = redirect;
                    break;
                }
            }

            if (loader.parsed_modules.find(dll_name) != loader.parsed_modules.end()) {
                resolve_imports(*loader.parsed_modules[dll_name], dll_name);
            }
            else {
                Logger::logf(Logger::Color::RED, "[!] DLL not parsed yet: %s -- skipping resolve", dll_name.c_str());
            }
        }

    }

