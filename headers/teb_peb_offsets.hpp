#pragma once
#include <unordered_map>
#include <string>

// TEB Offsets (relative to GS base)
#define TEB_OFFSET_SELF                          0x0030  
#define TEB_OFFSET_PEB                           0x0060  
#define TEB_OFFSET_LastErrorValue                0x0068
#define TEB_OFFSET_ClientId_UniqueProcess        0x0040
#define TEB_OFFSET_ClientId_UniqueThread         0x0048
#define TEB_OFFSET_EnvironmentPointer            0x0038
#define TEB_OFFSET_ActiveRpcHandle               0x0050
#define TEB_OFFSET_ThreadLocalStoragePointer     0x0058
#define TEB_OFFSET_CountOfOwnedCriticalSections  0x006C
#define TEB_OFFSET_CsrClientThread               0x0070
#define TEB_OFFSET_Win32ThreadInfo               0x0078
#define TEB_OFFSET_CurrentLocale                 0x0108
#define TEB_OFFSET_FPSoftwareStatusRegister      0x010C
#define TEB_OFFSET_DeallocationStack             0x1478
#define TEB_OFFSET_TLS_Slots                     0x1480
#define TEB_OFFSET_TLS_Links                     0x1680
#define TEB_OFFSET_GuaranteedStackBytes          0x1748

// PEB Offsets (relative to PEB pointer from GS:[0x60])
#define PEB_OFFSET_InheritedAddressSpace         0x0000
#define PEB_OFFSET_ReadImageFileExecOptions      0x0001
#define PEB_OFFSET_BeingDebugged                 0x0002
#define PEB_OFFSET_BitField                      0x0003
#define PEB_OFFSET_Mutant                        0x0008
#define PEB_OFFSET_ImageBaseAddress              0x0010
#define PEB_OFFSET_Ldr                           0x0018
#define PEB_OFFSET_ProcessParameters             0x0020
#define PEB_OFFSET_SubSystemData                 0x0028
#define PEB_OFFSET_ProcessHeap                   0x0030
#define PEB_OFFSET_FastPebLock                   0x0038
#define PEB_OFFSET_AtlThunkSListPtr              0x0040
#define PEB_OFFSET_IFEOKey                       0x0048
#define PEB_OFFSET_CrossProcessFlags             0x0050
#define PEB_OFFSET_KernelCallbackTable           0x0058
#define PEB_OFFSET_SystemReserved                0x0060
#define PEB_OFFSET_AtlThunkSListPtr32            0x0064
#define PEB_OFFSET_ApiSetMap                     0x0068
#define PEB_OFFSET_TlsExpansionCounter           0x0070
#define PEB_OFFSET_TlsBitmap                     0x0078
#define PEB_OFFSET_TlsBitmapBits                 0x0080
#define PEB_OFFSET_ReadOnlySharedMemoryBase      0x0088
#define PEB_OFFSET_SharedData                    0x0090
#define PEB_OFFSET_ReadOnlyStaticServerData      0x0098
#define PEB_OFFSET_AnsiCodePageData              0x00A0
#define PEB_OFFSET_OemCodePageData               0x00A8
#define PEB_OFFSET_UnicodeCaseTableData          0x00B0
#define PEB_OFFSET_NumberOfProcessors            0x00B8
#define PEB_OFFSET_NtGlobalFlag                  0x00BC
#define PEB_OFFSET_CriticalSectionTimeout        0x00C0
#define PEB_OFFSET_HeapSegmentReserve            0x00C8
#define PEB_OFFSET_HeapSegmentCommit             0x00D0
#define PEB_OFFSET_HeapDeCommitTotalFreeThreshold 0x00D8
#define PEB_OFFSET_HeapDeCommitFreeBlockThreshold 0x00E0
#define PEB_OFFSET_NumberOfHeaps                 0x00E8
#define PEB_OFFSET_MaximumNumberOfHeaps          0x00EC
#define PEB_OFFSET_ProcessHeaps                  0x00F0
#define PEB_OFFSET_GdiSharedHandleTable          0x00F8
#define PEB_OFFSET_ProcessStarterHelper          0x0100
#define PEB_OFFSET_GdiDCAttributeList            0x0108
#define PEB_OFFSET_LoaderLock                    0x0110
#define PEB_OFFSET_OSMajorVersion                0x0118
#define PEB_OFFSET_OSMinorVersion                0x011C
#define PEB_OFFSET_OSBuildNumber                 0x0120
#define PEB_OFFSET_OSCSDVersion                  0x0122
#define PEB_OFFSET_OSPlatformId                  0x0124
#define PEB_OFFSET_ImageSubsystem                0x0128
#define PEB_OFFSET_ImageSubsystemMajorVersion    0x012C
#define PEB_OFFSET_ImageSubsystemMinorVersion    0x0130
#define PEB_OFFSET_ActiveProcessAffinityMask     0x0138
#define PEB_OFFSET_GdiHandleBuffer               0x0140  // 60 * 4 bytes = 240 bytes from here
#define PEB_OFFSET_PostProcessInitRoutine        0x0230
#define PEB_OFFSET_TlsExpansionBitmap            0x0238
#define PEB_OFFSET_TlsExpansionBitmapBits        0x0240
#define PEB_OFFSET_SessionId                     0x02C0
#define PEB_OFFSET_AppCompatFlags                0x02C8
#define PEB_OFFSET_AppCompatFlagsUser            0x02D0
#define PEB_OFFSET_pShimData                     0x02D8
#define PEB_OFFSET_AppCompatInfo                 0x02E0
#define PEB_OFFSET_CSDVersion                    0x02E8
#define PEB_OFFSET_ActivationContextData         0x02F0
#define PEB_OFFSET_ProcessAssemblyStorageMap     0x02F8
#define PEB_OFFSET_SystemDefaultActivationContextData 0x0300
#define PEB_OFFSET_SystemAssemblyStorageMap      0x0308
#define PEB_OFFSET_MinimumStackCommit            0x0310

#define TEB_OFFSET_StackBase                   0x0008
#define TEB_OFFSET_StackLimit                  0x0010
#define TEB_OFFSET_SubSystemTib                0x0018
#define TEB_OFFSET_FiberData                   0x0020
#define TEB_OFFSET_ArbitraryDataSlot           0x0028
#define TEB_OFFSET_EnvironmentPointer          0x0038
#define TEB_OFFSET_ActiveRPCHandle             0x0050
#define TEB_OFFSET_TLSArray                    0x0058
#define TEB_OFFSET_CsrClientThread             0x0070
#define TEB_OFFSET_Win32ThreadInfo             0x0078
#define TEB_OFFSET_Win32ClientInfo             0x0080
#define TEB_OFFSET_Wow64Reserved               0x0100
#define TEB_OFFSET_DeallocationStack           0x1478
#define TEB_OFFSET_TLS_Slots                   0x1480
#define TEB_OFFSET_TLS_Links                   0x1680
#define TEB_OFFSET_GuaranteedStackBytes        0x1748


