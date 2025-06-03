#include "../headers/PELoader.hpp"

std::unique_ptr<LIEF::PE::Binary> PELoader::load_pe_binary(const std::string& path) {
    auto binary = LIEF::PE::Parser::parse(path);
    if (!binary) {
        std::cerr << "[!] Failed to parse PE file: " << path << "\n";
        exit(1);
    }
    return binary;
}

std::string PELoader::get_exported_function_name(const std::string& dll_name, uint64_t address) {
    for (const auto& export_func : parsed_modules[dll_name]->exported_functions()) {
        std::cout << "Name: " << export_func.name() << "\n";
    }
    return "";
}

bool PELoader::dll_exists(const std::string& path) {
    return std::filesystem::exists(path);
}

void PELoader::add_to_parsed_moudal(std::string dll_name, std::unique_ptr<LIEF::PE::Binary> dll) {
    parsed_modules[dll_name] = std::move(dll);
}
