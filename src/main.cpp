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

    uint64_t main_program_start_address = 0x140000000;
    const std::string pe_name = "helloworld.exe";
    const std::string pe_path = "D:\\Project\\emulator\\binary\\"+ pe_name;

    auto binary = pe_loader.load_pe_binary(pe_path);


    emulator.map_pe_binary(*binary, main_program_start_address,pe_name);
    emulator.set_code_bounds(main_program_start_address,emulator.next_free_address, pe_name);

 
    pe_loader.loaded_modules[pe_name] = main_program_start_address;
    pe_loader.parsed_modules[pe_name] = std::move(binary);

    ImportResolver import_resolver(emulator.get_uc(), pe_loader, &emulator, "C:\\Windows\\System32\\");
    import_resolver.resolve_imports(*pe_loader.parsed_modules[pe_name], pe_name);
    import_resolver.resolve_imports_For_dlls(*pe_loader.parsed_modules[pe_name], pe_name);




    uint64_t entry_point = main_program_start_address + (pe_loader.parsed_modules[pe_name]->entrypoint() - pe_loader.parsed_modules[pe_name]->imagebase());
    emulator.set_entry_point(entry_point);


    HookContext hook_context{ &emulator, &import_resolver };
    emulator.setup_hooks(&hook_context); 

    emulator.setup_stack();
    emulator.setup_tls(*pe_loader.parsed_modules[pe_name], main_program_start_address);
    emulator.setup_TEB_PEB();
    emulator.map_kuser_shared_data();


    Logger::logf(Logger::Color::CYAN, "[+] Emulation started AT ADDRESS : 0x%llx", entry_point);
    emulator.start_emulation(entry_point);

    Logger::logf(Logger::Color::RED, "[-] Emulation ENDED .");
    getchar();
    return 0;
}
