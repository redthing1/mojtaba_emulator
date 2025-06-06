#pragma once

#include <unicorn/unicorn.h>
#include <iostream>
#include <LIEF/PE.hpp>
#include <dbghelp.h>
#include <windows.h>
#include <string>
#include <vector>
#include <winternl.h>
#include "PELoader.hpp"


#define STACK_ADDRESS 0x2000000
#define STACK_SIZE (2 * 1024 * 1024)
#define PAGE_SIZE 0x1000
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000

constexpr uint64_t GS_BASE = 0x0;
constexpr uint64_t GS_size = 1 * 1024 * 1024;


struct BinaryInfo {
    std::string name;
    uint64_t base;
    uint64_t size;
};

struct HookContext;

class Emulator {

    typedef struct _PEB {
        BYTE InheritedAddressSpace;
        BYTE ReadImageFileExecOptions;
        BYTE BeingDebugged;
        BYTE BitField;
        void* Mutant;
        void* ImageBaseAddress;
        void* Ldr;
        void* ProcessParameters;
        void* SubSystemData;
        void* ProcessHeap;
        void* FastPebLock;
        void* AtlThunkSListPtr;
        void* IFEOKey;
        union {
            UINT32 CrossProcessFlags;
            struct {
                UINT32 ProcessInJob : 1;
                UINT32 ProcessInitializing : 1;
                UINT32 ProcessUsingVEH : 1;
                UINT32 ProcessUsingVCH : 1;
                UINT32 ProcessUsingFTH : 1;
                UINT32 ReservedBits0 : 27;
            };
        };
        void* KernelCallbackTable;
        UINT32 SystemReserved;
        UINT32 AtlThunkSListPtr32;
        void* ApiSetMap;
        void* TlsExpansionCounter;
        void* TlsBitmap;
        UINT32 TlsBitmapBits[2];
        void* ReadOnlySharedMemoryBase;
        void* SharedData;
        void* ReadOnlyStaticServerData;
        void* AnsiCodePageData;
        void* OemCodePageData;
        void* UnicodeCaseTableData;
        UINT32 NumberOfProcessors;
        UINT32 NtGlobalFlag;
        UINT64 CriticalSectionTimeout;
        UINT64 HeapSegmentReserve;
        UINT64 HeapSegmentCommit;
        UINT64 HeapDeCommitTotalFreeThreshold;
        UINT64 HeapDeCommitFreeBlockThreshold;
        UINT32 NumberOfHeaps;
        UINT32 MaximumNumberOfHeaps;
        void** ProcessHeaps;
        void* GdiSharedHandleTable;
        void* ProcessStarterHelper;
        UINT32 GdiDCAttributeList;
        void* LoaderLock;
        UINT32 OSMajorVersion;
        UINT32 OSMinorVersion;
        UINT16 OSBuildNumber;
        UINT16 OSCSDVersion;
        UINT32 OSPlatformId;
        UINT32 ImageSubsystem;
        UINT32 ImageSubsystemMajorVersion;
        UINT32 ImageSubsystemMinorVersion;
        UINT64 ActiveProcessAffinityMask;
        UINT32 GdiHandleBuffer[60];
        void* PostProcessInitRoutine;
        void* TlsExpansionBitmap;
        UINT32 TlsExpansionBitmapBits[32];
        UINT32 SessionId;
        UINT64 AppCompatFlags;
        UINT64 AppCompatFlagsUser;
        void* pShimData;
        void* AppCompatInfo;
        void* CSDVersion;
        void* ActivationContextData;
        void* ProcessAssemblyStorageMap;
        void* SystemDefaultActivationContextData;
        void* SystemAssemblyStorageMap;
        UINT64 MinimumStackCommit;
    } PEB;

    typedef struct _NT_TIB {
        void* ExceptionList;         
        void* StackBase;           
        void* StackLimit;          
        void* SubSystemTib;        
        void* FiberData;           
        void* ArbitraryUserPointer;  
        void* Self;                 
    } NT_TIB;
    typedef struct _TEB {
        NT_TIB NtTib;
        void* EnvironmentPointer;
        CLIENT_ID ClientId;
        void* ActiveRpcHandle;
        void* ThreadLocalStoragePointer;
        PEB* ProcessEnvironmentBlock;
        UINT32 LastErrorValue;
        UINT32 CountOfOwnedCriticalSections;
        void* CsrClientThread;
        void* Win32ThreadInfo;
        UINT64 User32Reserved[26];
        UINT64 UserReserved[5];
        void* WOW32Reserved;
        UINT32 CurrentLocale;
        UINT32 FpSoftwareStatusRegister;
        void* SystemReserved1[54];
        INT64 ExceptionCode;
        void* ActivationContextStackPointer;
        UINT8 SpareBytes[36];
        UINT32 TxFsContext;
        void* InstrumentationCallback;  
        void* SubProcessTag;
        void* PerflibData;
        void* EtwTraceData;
        void* WinSockData;
        UINT32 GdiBatchCount;
        UINT32 IdealProcessorValue;
        UINT32 GuaranteedStackBytes;
        UINT32 ReservedForPerf;
        void* ReservedForOle;
        UINT32 WaitingOnLoaderLock;
        void* SavedPriorityState;
        UINT64 SoftPatchPtr1;
        void* ThreadPoolData;
        void* TlsExpansionSlots;
        UINT64 DeallocationStack;
        void* TlsSlots;
        void* DbgSsReserved;
        UINT32 HardErrorMode;
        UINT64 Instrumentation;
        void* WinSockLegacyData;
        void* ReservedForOle2;
        UINT64 TxnScopeEnterCallback;
        UINT64 TxnScopeExitCallback;
        UINT64 TxnScopeContext;
        UINT32 LockCount;
        UINT32 ProcessRundown;
        UINT64 LastSwitchTime;
        UINT64 TotalSwitchOutTime;
        UINT64 WaitReasonBitMap;
        UINT32 ContextSwitches;
        UINT32 SpareCounters[2];
        UINT32 IdealProcessor;
        UINT32 GuaranteedStackBytes2;
        void* ReservedForRtc;
    } TEB;

	PEB peb;
	TEB teb;

    uint64_t teb_addr;
    uint64_t peb_addr;


    std::vector<BinaryInfo> loaded_binaries;
    PELoader peloader;
    uc_engine* uc;

public:
    uint64_t main_code_start = 0;
    uint64_t main_code_end = 0;
    std::string main_binary_name;
    uint64_t next_free_address = 0x150000000;

    Emulator();
    ~Emulator();

    uc_engine* get_uc() const;

    size_t align_up(size_t size, size_t alignment);

    void set_code_bounds(uint64_t start, uint64_t end, const std::string& binary_name);

    uint64_t reserve_memory(size_t size, int perms = UC_PROT_ALL);

    PVOID GetPebFromTeb();

    void map_pe_binary(const LIEF::PE::Binary& binary, uint64_t load_base = 0, std::string name = "");

    void setup_stack();

    void map_kuser_shared_data();

    std::vector<uint8_t> build_TEB(uint64_t teb_addr, uint64_t peb_addr);

    std::vector<uint8_t> build_PEB();

    void setup_hooks(void* context);

    void set_entry_point(uint64_t entry_point);

    BinaryInfo* find_binary_by_address(uint64_t address);

    void emu_ret();

    std::string get_function_name_from_pdb(const std::string& dll_path, uint64_t rva);

    void start_emulation(uint64_t start_addr);

    bool isGsSegment(uint64_t addr);

    void CopyTebPebToBuffer(uint8_t* tebBuf, size_t tebSize, uint8_t* pebBuf, size_t pebSize);

    void setup_TEB_PEB();

    static bool hook_mem_read(uc_engine* uc, uc_mem_type type, uint64_t address,int size, int64_t value, void* user_data);

    static bool hook_mem_fetch_unmaped(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

    static bool hook_mem_read_unmaped(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
    
    void setup_tls(LIEF::PE::Binary &bin, uint64_t start_addr);

    static void code_hook_cb(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

    void is_hooked(uc_err err, std::string HookName);

    uint64_t Read_Pointer_reg(uc_x86_reg reg);
};
