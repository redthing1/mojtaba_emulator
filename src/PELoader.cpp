#include "../headers/PELoader.hpp"
#include "logger.cpp"

std::unique_ptr<LIEF::PE::Binary> PELoader::load_pe_binary(const std::string& path) {
    auto binary = LIEF::PE::Parser::parse(path);
    if (!binary) {
        Logger::logf(Logger::Color::RED, "[!] Failed to parse PE file: %s", path);
        exit(1);
    }
    return binary;
}


bool PELoader::dll_exists(const std::string& path) {
    return std::filesystem::exists(path);
}

void PELoader::add_to_parsed_moudal(std::string dll_name, std::unique_ptr<LIEF::PE::Binary> dll) {
    parsed_modules[dll_name] = std::move(dll);
}
