#pragma once
#include <unordered_map>
#include <string>


// TEB Offsets (relative to GS base)
#define TEB_OFFSET_SELF             0x00  // TEB*
#define TEB_OFFSET_PEB              0x30  // PEB*

// PEB Offsets (relative to PEB pointer from GS:[0x30])
#define PEB_OFFSET_ImageBaseAddress    0x10
#define PEB_OFFSET_Ldr                 0x18
#define PEB_OFFSET_ProcessParameters   0x20
#define PEB_OFFSET_SubSystemData       0x28
#define PEB_OFFSET_ProcessHeap         0x30
#define PEB_OFFSET_FastPebLock         0x38

