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

    std::unique_ptr<LIEF::PE::Binary> load_pe_binary(const std::string& path);
    bool dll_exists(const std::string& path);
    void add_to_parsed_moudal(std::string dll_name, std::unique_ptr<LIEF::PE::Binary> dll);
};
