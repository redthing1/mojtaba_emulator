#include "../headers/PELoader.hpp"
#include "../headers/Emulator.hpp"
#include "../headers/ImportResolver.hpp"
#include "logger.cpp"

    ImportResolver::ImportResolver(uc_engine* unicorn, PELoader& pe_loader, Emulator* emulator,std::string dll_path)
        : uc(unicorn), loader(pe_loader), emo(emulator),dll_path(dll_path) {
    }

    void ImportResolver::resolve_imports(const LIEF::PE::Binary& binary, std::string name) {
        log_needed_dlls(binary, name);

        for (const LIEF::PE::Import& import : binary.imports()) {
            std::string dll_name = resolve_library_name(import.name());

            if (!load_dll_if_needed(dll_name, name)) {
                continue;
            }

            uint64_t dll_base = loader.loaded_modules[dll_name];
            const auto& export_object = loader.parsed_modules[dll_name]->get_export();

            for (const auto& func : import.entries()) {
                uint64_t resolved_addr = resolve_function_address(func, dll_name, dll_base);

                if (resolved_addr == 0) {
                    continue;
                }

                patch_iat_entry(name, func.iat_address(), resolved_addr);
            }
        }
    }
    std::string ImportResolver::resolve_library_name(const std::string& original_name) {
        for (const auto& [prefix, redirect] : api_set_redirects) {
            if (original_name.rfind(prefix, 0) == 0) {
                return redirect;
            }
        }
        return original_name;
    }

    uint64_t ImportResolver::resolve_function_address(const LIEF::PE::ImportEntry& func,const std::string& dll_name, uint64_t dll_base) {
        if (!func.is_ordinal()) {
            std::string func_name = func.name();

            for (const auto& exported_func : loader.parsed_modules[dll_name]->exported_functions()) {
                if (func_name == exported_func.name()) {
                    return dll_base + exported_func.address();
                }
            }

            // Try fallback ntdll.dll
            if (func_name.rfind("Rtl", 0) == 0 || func_name.rfind("Nt", 0) == 0) {
                std::string fallback_dll = "ntdll.dll";
                if (loader.loaded_modules.find(fallback_dll) == loader.loaded_modules.end()) {
                    std::string fallback_path = "D:\\Project\\emulator\\Dlls\\" + fallback_dll;
                    if (std::filesystem::exists(fallback_path)) {
                        auto dll = loader.load_pe_binary(fallback_path);
                        uint64_t fallback_base = emo->reserve_memory(dll->optional_header().sizeof_image());
                        emo->map_pe_binary(*dll, fallback_base, fallback_dll);
                        loader.loaded_modules[fallback_dll] = fallback_base;
                        loader.add_to_parsed_moudal(fallback_dll, std::move(dll));
                    }
                }

                uint64_t ntdll_base = loader.loaded_modules[fallback_dll];
                for (const auto& exported_func : loader.parsed_modules[fallback_dll]->exported_functions()) {
                    if (func_name == exported_func.name()) {
                        return ntdll_base + exported_func.address();
                    }
                }
            }

            // Search in all loaded modules
            for (const auto& [mod_name, mod_base] : loader.loaded_modules) {
                for (const auto& exported_func : loader.parsed_modules[mod_name]->exported_functions()) {
                    if (func_name == exported_func.name()) {
                        return mod_base + exported_func.address();
                    }
                }
            }

            Logger::logf(Logger::Color::RED, "[!] Failed to resolve import: %s", func_name.c_str());
            return 0;
        }
        else {
            uint16_t ordinal = static_cast<uint16_t>(func.data());
            const auto& export_entries = loader.parsed_modules[dll_name]->get_export()->entries();
            for (const auto& export_entry : export_entries) {
                if (export_entry.ordinal() == ordinal) {
                    return dll_base + export_entry.address();
                }
            }

            Logger::logf(Logger::Color::RED, "[!] Failed to resolve ordinal import #%d", ordinal);
            return 0;
        }
    }

    void ImportResolver::patch_iat_entry(const std::string& module_name, uint64_t iat_offset, uint64_t address) {
        if (uc_mem_write(this->uc, loader.loaded_modules[module_name] + iat_offset, &address, sizeof(address)) != UC_ERR_OK) {
            Logger::logf(Logger::Color::RED, "[!] Failed to patch IAT at 0x%llx", iat_offset);
        }
    }

    void ImportResolver::log_needed_dlls(const LIEF::PE::Binary& binary, const std::string& name) {
        for (const std::string& import : binary.imported_libraries()) {
            std::string display_name = resolve_library_name(import);
            if (name == emo->main_binary_name) {
                Logger::logf(Logger::Color::GRAY, "[*] %s Need DLL: %s .", emo->main_binary_name.c_str(), display_name.c_str());
            }
        }
    }

    bool ImportResolver::load_dll_if_needed(const std::string& dll_name, const std::string& for_module) {
        if (loader.parsed_modules.count(dll_name) && loader.loaded_modules.count(dll_name)) {
            return true;
        }

        std::string full_path = dll_path.empty()
            ? "C:\\Windows\\System32\\" + dll_name
            : dll_path + dll_name;

        if (!std::filesystem::exists(full_path)) {
            Logger::logf(Logger::Color::RED, "[!] DLL not found: %s — skipping (for: %s)", dll_name.c_str(), for_module.c_str());
            return false;
        }

        Logger::logf(Logger::Color::GRAY, "[*] Loading DLL: %s (for: %s)", dll_name.c_str(), for_module.c_str());

        try {
            auto dll = loader.load_pe_binary(full_path);
            uint64_t dll_base = emo->reserve_memory(dll->optional_header().sizeof_image());
            emo->map_pe_binary(*dll, dll_base, dll_name);
            loader.loaded_modules[dll_name] = dll_base;
            loader.add_to_parsed_moudal(dll_name, std::move(dll));
            return true;
        }
        catch (...) {
            Logger::logf(Logger::Color::RED, "[!] Failed to load DLL: %s", dll_name.c_str());
            return false;
        }
    }

    std::string  ImportResolver::function_name_resoler(const std::string& dll_name, uint64_t rva) {

            for (const auto& func : loader.parsed_modules[dll_name]->exported_functions()) {
                if (func.address() == rva) {
                    return func.name();
                }
            
         }
           
      //return dll_name + " + 0x" + std::to_string(rva);;
            return "";

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

