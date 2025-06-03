#include "../headers/PELoader.hpp"
#include "../headers/Emulator.hpp"
#include "../headers/ImportResolver.hpp"
#include "logger.cpp"

struct HookContext {
    Emulator* emulator;
    ImportResolver* resolver;
};


int main() {

    PELoader pe_loader;
    Emulator emulator;

    const std::string pe_name = "helloworld.exe";
    const std::string pe_path = "D:\\Project\\emulator\\binary\\"+ pe_name;

    auto binary = pe_loader.load_pe_binary(pe_path);

 
    emulator.map_pe_binary(*binary, 0x140000000,pe_name);
    emulator.set_code_bounds(0x140000000,emulator.next_free_address, pe_name);

    pe_loader.loaded_modules[pe_name] = 0x140000000;
    pe_loader.parsed_modules[pe_name] = std::move(binary);


    emulator.setup_stack();
    emulator.map_kuser_shared_data();



    uint64_t entry_point = pe_loader.parsed_modules[pe_name]->entrypoint() ;
    emulator.set_entry_point(entry_point);

    ImportResolver import_resolver(emulator.get_uc(), pe_loader, &emulator);
    import_resolver.resolve_imports(*pe_loader.parsed_modules[pe_name], pe_name);
    import_resolver.resolve_imports_For_dlls(*pe_loader.parsed_modules[pe_name], pe_name);

    HookContext hook_context{ &emulator, &import_resolver };
    emulator.setup_hooks(&hook_context); // hook All the calls 
    Logger::logf(Logger::Color::CYAN, "[+] Emulation started AT ADDRESS : 0x%llx", entry_point);
    emulator.start_emulation(entry_point);

    Logger::logf(Logger::Color::RED, "[-] Emulation ENDED .");
    getchar();
    return 0;
}
