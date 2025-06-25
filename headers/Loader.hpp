#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <unicorn/unicorn.h>
#include <unordered_map>

struct CpuRegisters {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, eflags;

    uint64_t xmm[16][16];
};
struct DebugState {
    DEBUG_EVENT lastEvent;
    bool hasPendingEvent = false;
};
typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;


struct MemoryRegion {
    uint64_t base;
    size_t size;
    std::string name;

    MemoryRegion(uint64_t b, size_t s, const std::string& n = "") : base(b), size(s), name(n) {}
};


class ProcessLoader {
    bool isTlsMode_ = false;
    DebugState lastDebugState;
    DWORD tlsThreadId_ = 0;
    DWORD targetThreadId_ = 0;
    uint64_t breakpointAddress_ = 0;
    std::unordered_map<uint64_t, BYTE> originalBytes_;
    struct ExportedFunctionInfo {
        std::unordered_map<uint64_t, std::string> addrToName;
    };

    std::unordered_map<uint64_t, ExportedFunctionInfo> exportsCache_;
public:
    explicit ProcessLoader(const std::wstring& exePath);
    ~ProcessLoader();

    bool LoadAndInspect(uc_engine* unicorn);
    CpuRegisters GetRegisters();
    DWORD RvaToOffset(LPVOID fileBase, DWORD rva);
    std::wstring GetModuleNameByAddress(uint64_t address);
    void LoadAllMemoryRegionsToUnicorn(uc_engine* unicorn);
    MemoryRegion GetMemoryRegionByName(const std::string& name) const;
    std::vector<MemoryRegion> GetMemoryRegion();
    bool MapSingleMemoryPageToUnicorn(uc_engine* unicorn, uint64_t address);
    std::string GetExportedFunctionNameByAddress(uint64_t addr);
    bool RemoveBreakpoint();
    bool resume_program();
    bool SetBreakpoint(void* address);
    void DebugLoop(uc_engine* unicorn);
    bool IsThreadAtBreakpoint( uint64_t breakpointAddress);
private:
    std::wstring exePath_;
    PROCESS_INFORMATION pi_{};
    bool initialized_;
    std::vector<MemoryRegion> memoryRegions_;
    uint64_t GetTEBAddress(DWORD threadId);
    bool CreateTargetProcess();
    LPVOID GetEntryPointAddress();
    std::vector<LPVOID> GetAllTLSCallbackAddresses();
    bool SetBreakpointAtStartup(uc_engine* unicorn);
    std::string GetMappedFileNameAtAddress(LPVOID base);
    void DebugLoop();

    void Cleanup();
};
