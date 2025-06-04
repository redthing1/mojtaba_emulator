#pragma once

enum class DllId {
    Kernel32,
    User32,
    Gdi32,
    KERNELBASE,
    Unknown
};


inline DllId GetDllIdFromString(const std::string& dllName) {
    if (dllName == "KERNEL32.dll") return DllId::Kernel32;
    if (dllName == "USER32.dll") return DllId::User32;
    if (dllName == "KERNELBASE.dll") return DllId::KERNELBASE;
    if (dllName == "gdi32.dll") return DllId::Gdi32;
    return DllId::Unknown;
}
