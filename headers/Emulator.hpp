#pragma once

#include <unicorn/unicorn.h>
#include "Loader.hpp"
#include <map>
#include <string>

static const std::map<uint64_t, std::string> kuser_shared_data_offsets = {
    {0x000, "TickCountLowDeprecated"},
    {0x004, "TickCountMultiplier"},
    {0x008, "InterruptTime"},
    {0x010, "SystemTime"},
    {0x018, "TimeZoneBias"},
    {0x020, "ImageNumberLow"},
    {0x024, "ImageNumberHigh"},
    {0x028, "NtSystemRoot"}, // WCHAR*
    {0x02C, "MaxStackTraceDepth"},
    {0x030, "CryptoExponent"},
    {0x034, "TimeZoneId"},
    {0x038, "LargePageMinimum"},
    {0x040, "AitSamplingValue"},
    {0x044, "AppCompatFlag"},
    {0x048, "RNGSeedVersion"},
    {0x050, "GlobalValidationRunlevel"},
    {0x054, "TimeZoneBiasStamp"},
    {0x058, "NtBuildNumber"},
    {0x05C, "NtProductType"},
    {0x060, "ProductTypeIsValid"},
    {0x064, "Reserved0"},
    {0x068, "NtMajorVersion"},
    {0x06C, "NtMinorVersion"},
    {0x070, "ProcessorFeatures"},  // 64 bytes (2 * 32-bit arrays)
    {0x0B0, "Reserved1"},
    {0x0C0, "Reserved2"},
    {0x0F0, "NXSupportPolicy"},
    {0x0F4, "GdiHandleBuffer"},
    {0x100, "UserModeGlobalLogger"},
    {0x180, "HeapTracingThreshold"},
    {0x188, "CritSecTracingThreshold"},
    {0x190, "SuiteMask"},
    {0x194, "KdDebuggerEnabled"},
    {0x198, "MitigationPolicies"},
    {0x1A0, "CyclesPerYield"},
    {0x1A4, "XStateCompactionEnabled"},
    {0x1A8, "ProcessCookie"},
    {0x1B0, "ConsoleSessionForegroundProcessId"},
    {0x1B4, "TimeUpdateLock"},
    {0x1B8, "BaselineSystemTimeQpc"},
    {0x1C0, "BaselineInterruptTimeQpc"},
    {0x1C8, "QpcSystemTimeIncrement"},
    {0x1D0, "QpcInterruptTimeIncrement"},
    {0x1D8, "QpcSystemTimeIncrementShift"},
    {0x1DC, "QpcInterruptTimeIncrementShift"},
    {0x1E0, "QpcSystemTimeIncrementScale"},
    {0x1E8, "QpcInterruptTimeIncrementScale"},
    {0x1F0, "UserModeSharedPerformanceCounters"},
    {0x260, "TickCount"},
    {0x268, "TickCountQuad"},
    {0x270, "ReservedTickCountOverlay"},
    {0x2D0, "TimeSlip"},
    {0x2D4, "Reserved3"},
    {0x2E0, "SystemExpirationDate"},
    {0x2F0, "KdDebuggerNotPresent"},
    {0x2F4, "ActiveConsoleId"},
    {0x2F8, "DismountCount"},
    {0x2FC, "ComPlusPackage"},
    {0x300, "LastSystemRITEventTickCount"},
    {0x308, "NumberOfPhysicalPages"},
    {0x310, "SafeBootMode"},
    {0x314, "SharedDataFlags"},
    {0x318, "DbgErrorPortPresent"},
    {0x31C, "DbgElevationEnabled"},
    {0x320, "DbgVirtEnabled"},
    {0x324, "DbgInstallerDetectEnabled"},
    {0x328, "SystemDllNativeRelocation"},
    {0x32C, "DbgDynProcessorEnabled"},
    {0x330, "DbgSEHValidationEnabled"},
    {0x338, "QpcFrequency"},
    {0x340, "QpcShift"},
    {0x348, "QpcBias"},
    {0x350, "QpcBiasUserModeAccurate"},
    {0x360, "ActiveProcessorCount"},
    {0x364, "ActiveGroupCount"},
    {0x368, "Reserved4"},
    {0x370, "VolatileEnvironmentChecksum"},
    {0x378, "TelemetryCoverageHeader"},
    {0x380, "WheaErrorInjectionInterface"},
    {0x388, "EtwLoggerId"},
    {0x390, "ConsoleInputIdle"},
    {0x394, "TimeSinceLastInput"},
    {0x398, "PendingHotplugEvent"},
    {0x3A0, "UserCapFlags"},
    {0x3A4, "SafeBootModePolicy"},
};
static const std::map<uint64_t, std::string> teb_offsets = {
    {0x30, "ThreadLocalStoragePointer"},
    {0x58, "ClientId (ProcessId, ThreadId)"},
    {0x60, "ProcessEnvironmentBlock (PEB*)"},
    {0x148, "ThreadInfoBlock"},
    {0x2c8, "ActiveFrame"},
    {0x17f8, "ExceptionList"},
};

static const std::map<uint64_t, std::string> peb_offsets = {
    {0x000, "InheritedAddressSpace"},
    {0x002, "ReadImageFileExecOptions"},
    {0x003, "BeingDebugged"},
    {0x010, "ImageBaseAddress"},
    {0x018, "Ldr (PEB_LDR_DATA*)"},
    {0x020, "ProcessParameters"},
    {0x068, "SessionId"},
    {0x0F8, "AppCompatFlags"},
    {0x110, "CSDVersion"},
};

class Emulator {

public:
  
    Emulator(const std::string& exePath, const std::string& exeName);
    ~Emulator();

    bool initialize();
    bool start();

private:
    static void hook_syscall(uc_engine* uc, void* user_data);
    static void hook_cpuid(uc_engine* uc, void* user_data);
    static void hook_mem_write(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
    static void hook_mem_read(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
    static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static void hook_code_block(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
    void ReloadAtAddress(uint64_t address);
    uint64_t Poi(uc_x86_reg reg);
    std::string exeName;
    std::wstring wExeName;
    ProcessLoader loader;
    uc_engine* unicorn = nullptr;
    uint64_t instruction_count = 0;
};
