#pragma once
#include <LIEF/PE.hpp>
#include <iostream>
#include <filesystem>
#include <map>
#include <memory>

class PELoader {
public:
    std::map<std::string, uint64_t> loaded_modules;
    std::map<std::string, std::unique_ptr<LIEF::PE::Binary>> parsed_modules;

    std::unique_ptr<LIEF::PE::Binary> load_pe_binary(const std::string& path) {
        auto binary = LIEF::PE::Parser::parse(path);
        if (!binary) {
            std::cerr << "[!] Failed to parse PE file: " << path << "\n";
            exit(1);
        }
        return binary;
    }

    bool dll_exists(const std::string& path) {

        return std::filesystem::exists(path);
    }
};
