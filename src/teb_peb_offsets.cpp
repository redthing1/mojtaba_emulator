#include "../headers/teb_peb_offsets.hpp"

std::unordered_map<uint64_t, const char*> gs_offset_names = {
    {TEB_OFFSET_SELF,              "TEB (self pointer)"},
    {TEB_OFFSET_PEB,               "PEB pointer"},
    {PEB_OFFSET_ImageBaseAddress,  "PEB.ImageBaseAddress"},
    {PEB_OFFSET_Ldr,               "PEB.Ldr"},
    {PEB_OFFSET_ProcessParameters, "PEB.ProcessParameters"},
    {PEB_OFFSET_ProcessHeap,       "PEB.ProcessHeap"},
};