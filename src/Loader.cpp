#include "../headers/Loader.hpp"
#include <Windows.h>
#include <TlHelp32.h>
#include <unicorn/unicorn.h>
#include "../src/Logger.cpp" 

#pragma comment(lib, "ntdll.lib")

ProcessLoader::ProcessLoader(const std::wstring& exePath)
    : exePath_(exePath), initialized_(false) {
    ZeroMemory(&pi_, sizeof(pi_));
    Logger::logf(Logger::Color::GREEN, "[+] ProcessLoader created for: %ls", exePath_.c_str());
}

ProcessLoader::~ProcessLoader() {
    Logger::logf(Logger::Color::GREEN, "[+] Destructor called, cleaning up...");
    Cleanup();
}

bool ProcessLoader::LoadAndInspect(uc_engine* unicorn) {
    Logger::logf(Logger::Color::GREEN, "[+] Starting process creation and inspection...");
    if (!CreateTargetProcess()) return false;
    if (!SetBreakpointAtStartup(unicorn)) return false;
    DebugLoop();
    return true;
}

bool ProcessLoader::CreateTargetProcess() {
    STARTUPINFOW si = { sizeof(si) };
    if (CreateProcessW(exePath_.c_str(), nullptr, nullptr, nullptr, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi_)) {
        initialized_ = true;
        Logger::logf(Logger::Color::GREEN, "[+] Process created successfully.");
        return true;
    }
    Logger::logf(Logger::Color::RED, "[-] CreateProcessW failed: %lu", GetLastError());
    return false;
}
LPVOID ProcessLoader::GetEntryPointAddress() {


    PROCESS_BASIC_INFORMATION pbi{};
    if (NtQueryInformationProcess(pi_.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0)
        return nullptr;


    PEB peb{};
    if (!ReadProcessMemory(pi_.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) return nullptr;

    BYTE* imageBase = reinterpret_cast<BYTE*>(peb.Reserved3[1]);


    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};

    if (!ReadProcessMemory(pi_.hProcess, imageBase, &dos, sizeof(dos), nullptr)) return nullptr;
    if (!ReadProcessMemory(pi_.hProcess, imageBase + dos.e_lfanew, &nt, sizeof(nt), nullptr)) return nullptr;

    return imageBase + nt.OptionalHeader.AddressOfEntryPoint;
}


std::vector<LPVOID> ProcessLoader::GetAllTLSCallbackAddresses() {
    std::vector<LPVOID> callbacks;

    PROCESS_BASIC_INFORMATION pbi{};
    if (NtQueryInformationProcess(pi_.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0)
        return callbacks;

    PEB peb{};
    if (!ReadProcessMemory(pi_.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) return callbacks;

    BYTE* imageBase = reinterpret_cast<BYTE*>(peb.Reserved3[1]);
    IMAGE_DOS_HEADER dos{};
    if (!ReadProcessMemory(pi_.hProcess, imageBase, &dos, sizeof(dos), nullptr)) return callbacks;

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(pi_.hProcess, imageBase + dos.e_lfanew, &nt, sizeof(nt), nullptr)) return callbacks;

    IMAGE_DATA_DIRECTORY tlsDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0) return callbacks;

    IMAGE_TLS_DIRECTORY64 tls{};
    if (!ReadProcessMemory(pi_.hProcess, imageBase + tlsDir.VirtualAddress, &tls, sizeof(tls), nullptr)) return callbacks;

    ULONGLONG addr = tls.AddressOfCallBacks;
    if (addr == 0) return callbacks;

    while (true) {
        ULONGLONG cbVA = 0;
        if (!ReadProcessMemory(pi_.hProcess, reinterpret_cast<LPCVOID>(addr), &cbVA, sizeof(cbVA), nullptr))
            break;
        if (cbVA == 0) break;
        callbacks.push_back(reinterpret_cast<LPVOID>(cbVA));
        addr += sizeof(ULONGLONG);
    }

    return callbacks;
}



bool ProcessLoader::SetBreakpointAtStartup(uc_engine* unicorn) {
    auto callbacks = GetAllTLSCallbackAddresses();
    isTlsMode_ = !callbacks.empty();

    if (!isTlsMode_) {
        Logger::logf(Logger::Color::YELLOW, "[-] No TLS callbacks found. Falling back to entry point.");
        LPVOID entry = GetEntryPointAddress();
        if (!entry) {
            Logger::logf(Logger::Color::RED, "[-] No valid entry point address.");
            return false;
        }
        callbacks.push_back(entry);
    }

    for (auto bpAddr : callbacks) {
        BYTE originalByte = 0;
        if (!ReadProcessMemory(pi_.hProcess, bpAddr, &originalByte, 1, nullptr)) continue;

        originalBytes_[(uint64_t)bpAddr] = originalByte;
        BYTE int3 = 0xCC;
        if (!WriteProcessMemory(pi_.hProcess, bpAddr, &int3, 1, nullptr)) continue;
        FlushInstructionCache(pi_.hProcess, bpAddr, 1);

        breakpointAddress_ = (uint64_t)bpAddr;
        Logger::logf(Logger::Color::GREEN, "[+] Breakpoint set at 0x%llx", breakpointAddress_);
        break;
    }

    if (ResumeThread(pi_.hThread) == (DWORD)-1) {
        Logger::logf(Logger::Color::RED, "[-] ResumeThread failed: %lu", GetLastError());
        return false;
    }
    return true;
}

bool ProcessLoader::IsThreadAtBreakpoint( uint64_t breakpointAddress) {
    HANDLE hThread = pi_.hThread;
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;

#ifdef _WIN64
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        return false;
    }

    bool isAtBp = (ctx.Rip == breakpointAddress);
#else
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        return false;
    }

    bool isAtBp = (ctx.Eip == breakpointAddress);
#endif

    ResumeThread(hThread);
    return isAtBp;
}
void ProcessLoader::DebugLoop() {
    DEBUG_EVENT dbgEvent;
    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

            DWORD hitThreadId = dbgEvent.dwThreadId;
            lastDebugState.lastEvent = dbgEvent;
            lastDebugState.hasPendingEvent = true;
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, hitThreadId);
            if (!hThread) {
                Logger::logf(Logger::Color::RED, "[-] OpenThread failed for thread %lu", hitThreadId);
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                continue;
            }

            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(hThread, &ctx)) {
                CloseHandle(hThread);
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                continue;
            }

            if (ctx.Rip == breakpointAddress_ + 1 || ctx.Rip == breakpointAddress_) {
                ctx.Rip = breakpointAddress_;
                SetThreadContext(hThread, &ctx);
                tlsThreadId_ = hitThreadId;
                CloseHandle(hThread);
                break;
            }
            CloseHandle(hThread);
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }
}

void ProcessLoader::DebugLoop(uc_engine* unicorn) {
    DEBUG_EVENT dbgEvent;
    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

            DWORD hitThreadId = dbgEvent.dwThreadId;
            lastDebugState.lastEvent = dbgEvent;
            lastDebugState.hasPendingEvent = true;
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, hitThreadId);
            if (!hThread) {
                Logger::logf(Logger::Color::RED, "[-] OpenThread failed for thread %lu", hitThreadId);
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                continue;
            }

            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(hThread, &ctx)) {
                CloseHandle(hThread);
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                continue;
            }


            if (ctx.Rip == breakpointAddress_ + 1 || ctx.Rip == breakpointAddress_) {
                ctx.Rip = breakpointAddress_;
                SetThreadContext(hThread, &ctx);


                LoadAllMemoryRegionsToUnicorn(unicorn);

                tlsThreadId_ = hitThreadId;
                CloseHandle(hThread);
                break;
            }
            CloseHandle(hThread);
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }
}


CpuRegisters ProcessLoader::GetRegisters() {
    CONTEXT ctx = { .ContextFlags = CONTEXT_ALL };
    CpuRegisters regs{};

    HANDLE hThread = (tlsThreadId_ != GetThreadId(pi_.hThread))
        ? OpenThread(THREAD_ALL_ACCESS, FALSE, tlsThreadId_)
        : pi_.hThread;

    if (!hThread) return regs;
    if (GetThreadContext(hThread, &ctx)) {
        regs.rax = ctx.Rax; regs.rbx = ctx.Rbx;
        regs.rcx = ctx.Rcx; regs.rdx = ctx.Rdx;
        regs.rsi = ctx.Rsi; regs.rdi = ctx.Rdi;
        regs.rbp = ctx.Rbp; regs.rsp = ctx.Rsp;
        regs.r8 = ctx.R8;   regs.r9 = ctx.R9;
        regs.r10 = ctx.R10; regs.r11 = ctx.R11;
        regs.r12 = ctx.R12; regs.r13 = ctx.R13;
        regs.r14 = ctx.R14; regs.r15 = ctx.R15;
        regs.rip = ctx.Rip;
    }

    if (hThread != pi_.hThread) CloseHandle(hThread);
   // Logger::logf(Logger::Color::GREEN, "[+] Registers captured from Thread ID: %lu", tlsThreadId_);
    return regs;
}

void ProcessLoader::LoadAllMemoryRegionsToUnicorn(uc_engine* unicorn) {
    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQueryEx(pi_.hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        DWORD prot = mbi.Protect & 0xFF;
        bool readable = (prot & PAGE_READONLY) || (prot & PAGE_READWRITE) ||
            (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE);

        if (mbi.State == MEM_COMMIT && readable && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_PRIVATE)) {
            std::vector<uint8_t> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(pi_.hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                int ucProt = 0;
                switch (prot) {
                case PAGE_READONLY: ucProt = UC_PROT_READ; break;
                case PAGE_READWRITE:
                case PAGE_WRITECOPY: ucProt = UC_PROT_READ | UC_PROT_WRITE; break;
                case PAGE_EXECUTE: ucProt = UC_PROT_EXEC; break;
                case PAGE_EXECUTE_READ: ucProt = UC_PROT_EXEC | UC_PROT_READ; break;
                case PAGE_EXECUTE_READWRITE:
                case PAGE_EXECUTE_WRITECOPY: ucProt = UC_PROT_EXEC | UC_PROT_READ | UC_PROT_WRITE; break;
                default: ucProt = UC_PROT_ALL; break;
                }

                bool alreadyMapped = false;
                for (const MemoryRegion& region : memoryRegions_) {
                    uint64_t base = region.base;
                    size_t size = region.size;
                    if ((uint64_t)mbi.BaseAddress >= base && (uint64_t)mbi.BaseAddress < base + size) {
                        alreadyMapped = true;
                        break;
                    }
                }

                if (!alreadyMapped) {
                    uc_err err = uc_mem_map(unicorn, (uint64_t)mbi.BaseAddress, mbi.RegionSize, ucProt);
                    if (err != UC_ERR_OK) {
                        Logger::logf(Logger::Color::YELLOW, "[*] uc_mem_map failed with prot 0x%x at 0x%llx, retrying with UC_PROT_ALL...", ucProt, (uint64_t)mbi.BaseAddress);
                        err = uc_mem_map(unicorn, (uint64_t)mbi.BaseAddress, mbi.RegionSize, UC_PROT_ALL);
                        if (err != UC_ERR_OK) {
                            Logger::logf(Logger::Color::RED, "[-] uc_mem_map still failed at 0x%llx", (uint64_t)mbi.BaseAddress);
                            addr += mbi.RegionSize;
                            continue;
                        }
                    }
                }

                for (auto& [patchAddr, origByte] : originalBytes_) {
                    if (patchAddr >= (uint64_t)mbi.BaseAddress && patchAddr < (uint64_t)mbi.BaseAddress + bytesRead) {
                        buffer[patchAddr - (uint64_t)mbi.BaseAddress] = origByte;
                    }
                }

                uc_mem_write(unicorn, (uint64_t)mbi.BaseAddress, buffer.data(), bytesRead);

                if (!alreadyMapped) {
                    std::string regionName = GetMappedFileNameAtAddress(mbi.BaseAddress);
                    memoryRegions_.emplace_back((uint64_t)mbi.BaseAddress, mbi.RegionSize, regionName);
                }
            }
        }
        addr += mbi.RegionSize;
    }

    const CpuRegisters& regs = GetRegisters();
    struct {
        int id;
        uint64_t val;
    } reg_map[] = {
        { UC_X86_REG_RAX, regs.rax },
        { UC_X86_REG_RBX, regs.rbx },
        { UC_X86_REG_RCX, regs.rcx },
        { UC_X86_REG_RDX, regs.rdx },
        { UC_X86_REG_RSI, regs.rsi },
        { UC_X86_REG_RDI, regs.rdi },
        { UC_X86_REG_RBP, regs.rbp },
        { UC_X86_REG_RSP, regs.rsp },
        { UC_X86_REG_RIP, regs.rip },
        { UC_X86_REG_R8, regs.r8 },
        { UC_X86_REG_R9, regs.r9 },
        { UC_X86_REG_R10, regs.r10 },
        { UC_X86_REG_R11, regs.r11 },
        { UC_X86_REG_R12, regs.r12 },
        { UC_X86_REG_R13, regs.r13 },
        { UC_X86_REG_R14, regs.r14 },
        { UC_X86_REG_R15, regs.r15 }
    };
    for (auto& r : reg_map) {
        uc_reg_write(unicorn, r.id, &r.val);
    }

    uint64_t teb = GetTEBAddress(tlsThreadId_);
    uc_reg_write(unicorn, UC_X86_REG_GS_BASE, &teb);
    // Logger::logf(Logger::Color::GREEN, "[+] GS Base set to TEB address: 0x%llx", teb);
}




std::wstring ProcessLoader::GetModuleNameByAddress(uint64_t address) {
    for (const auto& region : memoryRegions_) {
        if (address >= region.base && address < region.base + region.size) {
            return region.name.empty() ? L"(unknown)" : std::wstring(region.name.begin(), region.name.end());
        }
    }
    return L"(not found)";
}

uint64_t ProcessLoader::GetTEBAddress(DWORD threadId) {

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) return 0;

    THREAD_BASIC_INFORMATION tbi{};
    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), nullptr);
    CloseHandle(hThread);
    return status == 0 ? reinterpret_cast<uint64_t>(tbi.TebBaseAddress) : 0;
}

MemoryRegion ProcessLoader::GetMemoryRegionByName(const std::string& name) const {
    uint64_t minBase = UINT64_MAX;
    uint64_t maxEnd = 0;

    for (const auto& region : memoryRegions_) {
        if (region.name == name) {
            if (region.base < minBase)
                minBase = region.base;

            uint64_t end = region.base + region.size;
            if (end > maxEnd)
                maxEnd = end;
        }
    }

    if (minBase == UINT64_MAX || maxEnd == 0)
        return MemoryRegion(0, 0, ""); // Not found

    return MemoryRegion(minBase, maxEnd - minBase, name);
}

std::vector<MemoryRegion> ProcessLoader::GetMemoryRegion() {
    return memoryRegions_;
}

std::string ProcessLoader::GetMappedFileNameAtAddress(LPVOID base) {
    char filename[MAX_PATH] = { 0 };
    if (GetMappedFileNameA(pi_.hProcess, base, filename, MAX_PATH)) {
        std::string fullPath(filename);
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return fullPath.substr(lastSlash + 1);
        }
        return fullPath;
    }
    return "";
}
bool ProcessLoader::MapSingleMemoryPageToUnicorn(uc_engine* unicorn, uint64_t address) {
    constexpr size_t pageSize = 0x1000;
    uint64_t pageBase = address & ~(pageSize - 1);

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T result = VirtualQueryEx(pi_.hProcess, reinterpret_cast<LPCVOID>(pageBase), &mbi, sizeof(mbi));
    if (result != sizeof(mbi)) {
       Logger::logf(Logger::Color::RED, "[-] VirtualQueryEx failed at 0x%llx (returned size = 0x%llx), error = %lu",pageBase, result, GetLastError());
        return false;
    }

  //  Logger::logf(Logger::Color::CYAN,"[*] VirtualQueryEx: Base=0x%llx, RegionSize=0x%llx, State=0x%lx, Protect=0x%lx, Type=0x%lx",reinterpret_cast<uint64_t>(mbi.BaseAddress),mbi.RegionSize,mbi.State,mbi.Protect,mbi.Type);

    DWORD prot = mbi.Protect;

    // Check if already mapped
    for (const auto& region : memoryRegions_) {
        if (pageBase >= region.base && pageBase < region.base + region.size) {
            Logger::logf(Logger::Color::YELLOW,
                "[!] Page 0x%llx already mapped (inside region base=0x%llx size=0x%llx).",
                pageBase, region.base, region.size);
            return true;
        }
    }

    // Determine UC protection flags
    auto GetUnicornProtection = [](DWORD protect) -> int {
        int flags = UC_PROT_READ;
        if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            flags |= UC_PROT_EXEC;
        if (protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            flags |= UC_PROT_WRITE;
        return flags;
        };

    bool readable = (prot & PAGE_READONLY) || (prot & PAGE_READWRITE) ||
        (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE);

    if ((prot & PAGE_GUARD) || prot == PAGE_NOACCESS || !(mbi.State == MEM_COMMIT && readable)) {
      //  Logger::logf(Logger::Color::YELLOW,
       //     "[!] Memory page 0x%llx has limited access (State=0x%lx, prot=0x%lx), trying ReadProcessMemory fallback.",
       //     pageBase, mbi.State, prot);

        std::vector<uint8_t> buffer(pageSize, 0);
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(pi_.hProcess, reinterpret_cast<LPCVOID>(pageBase), buffer.data(), pageSize, &bytesRead) && bytesRead > 0) {
          //  Logger::logf(Logger::Color::CYAN,
         //       "[*] ReadProcessMemory fallback succeeded: read 0x%llx bytes from 0x%llx",
          //      bytesRead, pageBase);

            int ucProt = GetUnicornProtection(prot);

            uc_err err = uc_mem_map(unicorn, pageBase, pageSize, ucProt);
            if (err != UC_ERR_OK) {
                Logger::logf(Logger::Color::RED,
                    "[-] uc_mem_map (fallback) failed at 0x%llx: %s",
                    pageBase, uc_strerror(err));
                return false;
            }

            uc_mem_write(unicorn, pageBase, buffer.data(), bytesRead);
            memoryRegions_.push_back({ pageBase, pageSize, "ReadMemoryFallback" });
          //  Logger::logf(Logger::Color::GREEN,
          //      "[+] Successfully mapped missing page @ 0x%llx with fallback.",
          //      pageBase);
            return true;
        }
        else {
            Logger::logf(Logger::Color::RED,
                "[-] ReadProcessMemory fallback failed at 0x%llx, error = %lu",
                pageBase, GetLastError());
            return false;
        }
    }

    // Standard case - fully accessible memory
    std::vector<uint8_t> buffer(pageSize);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(pi_.hProcess, reinterpret_cast<LPCVOID>(pageBase), buffer.data(), pageSize, &bytesRead) || bytesRead == 0) {
        Logger::logf(Logger::Color::RED,
            "[-] ReadProcessMemory failed at 0x%llx (bytesRead=0x%llx), error = %lu",
            pageBase, bytesRead, GetLastError());
        return false;
    }

    Logger::logf(Logger::Color::CYAN,
        "[*] Successfully read 0x%llx bytes from target at 0x%llx",
        bytesRead, pageBase);

    int ucProt = GetUnicornProtection(prot);

    Logger::logf(Logger::Color::CYAN,
        "[*] Mapping 0x%llx with UC protection 0x%x (Windows prot=0x%lx)",
        pageBase, ucProt, prot);

    uc_err err = uc_mem_map(unicorn, pageBase, pageSize, ucProt);
    if (err != UC_ERR_OK) {
        Logger::logf(Logger::Color::RED,
            "[-] uc_mem_map failed at 0x%llx: %s",
            pageBase, uc_strerror(err));
        return false;
    }

    uc_mem_write(unicorn, pageBase, buffer.data(), bytesRead);
    Logger::logf(Logger::Color::GREEN,
        "[+] Page at 0x%llx mapped to Unicorn with %llu bytes written.",
        pageBase, bytesRead);

    std::string name = GetMappedFileNameAtAddress(reinterpret_cast<void*>(pageBase));
    Logger::logf(Logger::Color::CYAN,
        "[*] Mapped file name for 0x%llx: %s",
        pageBase, name.c_str());

    memoryRegions_.push_back({ pageBase, pageSize, name });

    return true;
}




bool ProcessLoader::resume_program() {
    if (!initialized_) {
        Logger::logf(Logger::Color::RED, "[-] Process not initialized, cannot resume.");
        return false;
    }

    if (lastDebugState.hasPendingEvent) {
        if (ContinueDebugEvent(lastDebugState.lastEvent.dwProcessId,
            lastDebugState.lastEvent.dwThreadId,
            DBG_CONTINUE)) {
            lastDebugState.hasPendingEvent = false;
            //Logger::logf(Logger::Color::GREEN, "[+] Process resumed from suspended state.");
            return true;
        }
        else {
            Logger::logf(Logger::Color::RED, "[-] Failed to continue debug event: %lu", GetLastError());
            return false;
        }
    }

    Logger::logf(Logger::Color::YELLOW, "[*] No pending debug event to resume.");
    return false;
}

bool ProcessLoader::SetBreakpoint(void* address) {
    BYTE originalByte = 0;


    if (!ReadProcessMemory(pi_.hProcess, address, &originalByte, 1, nullptr)) {
        Logger::logf(Logger::Color::RED, "[-] Failed to read original byte at 0x%llx", (uint64_t)address);
        return false;
    }


    originalBytes_[(uint64_t)address] = originalByte;

    BYTE int3 = 0xCC;

    if (!WriteProcessMemory(pi_.hProcess, address, &int3, 1, nullptr)) {
        Logger::logf(Logger::Color::RED, "[-] Failed to write breakpoint at 0x%llx", (uint64_t)address);
        return false;
    }

    if (!FlushInstructionCache(pi_.hProcess, address, 1)) {
        Logger::logf(Logger::Color::YELLOW, "[!] FlushInstructionCache failed at 0x%llx", (uint64_t)address);
       
    }

    breakpointAddress_ = (uint64_t)address;
   // Logger::logf(Logger::Color::GREEN, "[+] Breakpoint set at 0x%llx", breakpointAddress_);

    return true;
}

std::string ProcessLoader::GetExportedFunctionNameByAddress(uint64_t addr) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(pi_.hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        Logger::logf(Logger::Color::RED, "[-] EnumProcessModules failed.");
        return "";
    }

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
        MODULEINFO modInfo;
        if (!GetModuleInformation(pi_.hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            continue;

        uint64_t base = reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
        uint64_t end = base + modInfo.SizeOfImage;
        if (addr < base || addr >= end)
            continue;


        auto it = exportsCache_.find(base);
        if (it != exportsCache_.end()) {
            auto& cache = it->second;
            auto found = cache.addrToName.find(addr);
            if (found != cache.addrToName.end())
                return found->second;
            else
                return "";
        }


        char path[MAX_PATH];
        if (!GetModuleFileNameExA(pi_.hProcess, hMods[i], path, MAX_PATH))
            continue;

        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            continue;

        HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping) {
            CloseHandle(hFile);
            continue;
        }

        LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!fileBase) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            continue;
        }

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBase;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + dos->e_lfanew);
        DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRVA) {
            UnmapViewOfFile(fileBase);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            continue;
        }

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)fileBase +
            RvaToOffset(fileBase, exportRVA));

        DWORD* functions = (DWORD*)((BYTE*)fileBase + RvaToOffset(fileBase, exportDir->AddressOfFunctions));
        DWORD* names = (DWORD*)((BYTE*)fileBase + RvaToOffset(fileBase, exportDir->AddressOfNames));
        WORD* ordinals = (WORD*)((BYTE*)fileBase + RvaToOffset(fileBase, exportDir->AddressOfNameOrdinals));

        ExportedFunctionInfo cache;
        for (DWORD j = 0; j < exportDir->NumberOfFunctions; ++j) {
            uint64_t funcAddr = base + functions[j];
            std::string funcName;
            for (DWORD k = 0; k < exportDir->NumberOfNames; ++k) {
                if (ordinals[k] == j) {
                    const char* name = (const char*)fileBase + RvaToOffset(fileBase, names[k]);
                    funcName = std::string(name);
                    break;
                }
            }
            cache.addrToName[funcAddr] = funcName;
        }

        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        exportsCache_[base] = std::move(cache);


        auto found = exportsCache_[base].addrToName.find(addr);
        if (found != exportsCache_[base].addrToName.end())
            return found->second;
        else
            return "";
    }

    return "";
}

DWORD ProcessLoader::RvaToOffset(LPVOID fileBase, DWORD rva) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD sectVA = section->VirtualAddress;
        DWORD sectSize = section->Misc.VirtualSize;
        if (rva >= sectVA && rva < sectVA + sectSize) {
            return section->PointerToRawData + (rva - sectVA);
        }
    }

    return rva;
}
bool ProcessLoader::RemoveBreakpoint() {
    auto it = originalBytes_.find(breakpointAddress_);
    if (it == originalBytes_.end()) return false;

    BYTE originalByte = it->second;
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi_.hProcess, (LPVOID)breakpointAddress_, &originalByte, 1, &bytesWritten) || bytesWritten != 1) {
        Logger::logf(Logger::Color::RED, "[-] Failed to restore original byte at 0x%llx", breakpointAddress_);
        return false;
    }
    FlushInstructionCache(pi_.hProcess, (LPVOID)breakpointAddress_, 1);
   // Logger::logf(Logger::Color::GREEN, "[+] Restored original byte at 0x%llx", breakpointAddress_);
    return true;
}

void ProcessLoader::Cleanup() {
    if (initialized_) {
        TerminateProcess(pi_.hProcess, 0);
        CloseHandle(pi_.hThread);
        CloseHandle(pi_.hProcess);
        initialized_ = false;
    }
}
