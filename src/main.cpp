#include "PELoader.cpp"
#include "Disassembler.cpp"
#include "Emulator.cpp"
#include "ImportResolver.cpp"


int main() {
    PELoader pe_loader;
    Emulator emulator;
    Disassembler disassembler;

    const std::string pe_path = "D:\\Project\\emulator\\binary\\helloworld.exe";
    const std::string pe_name = "helloworld.exe";

    auto binary = pe_loader.load_pe_binary(pe_path);

 
    emulator.map_pe_binary(*binary, 0x140000000);
    pe_loader.loaded_modules[pe_name] = 0x140000000;
    pe_loader.parsed_modules[pe_name] = std::move(binary);

    emulator.setup_stack();
    emulator.map_kuser_shared_data();



    uint64_t entry_point = pe_loader.parsed_modules[pe_name]->entrypoint() + 0x140000000;
    emulator.set_entry_point(entry_point);

    ImportResolver import_resolver(emulator.get_uc(), pe_loader, &emulator);
    import_resolver.resolve_imports(*pe_loader.parsed_modules[pe_name], pe_name);
    import_resolver.resolve_imports_For_dlls(*pe_loader.parsed_modules[pe_name], pe_name);
    // اگر نیاز بود resolve imports DLLs هم همینطور میشه اضافه کرد

    std::cout << "[+] Emulation started\n";
    emulator.start_emulation(entry_point);

    std::cout << "[+] Emulation ENDED!" << '\n';
    getchar();
    return 0;
}
