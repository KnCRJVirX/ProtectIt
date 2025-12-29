#ifndef HIDEWINDOW_H
#define HIDEWINDOW_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <stdint.h>
#include <Windows.h>
#include <winternl.h>

#include "protectordef.h"

#define RTL_CONSTANT_STRING(s) \
{ \
    sizeof( s ) - sizeof( (s)[0] ), \
    sizeof( s ), \
    (PWCH)(s) \
}

/* About PEB */

typedef struct _CURDIR {
  UNICODE_STRING DosPath;
  void *Handle;
} CURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  UINT16 Flags;
  UINT16 Length;
  unsigned int TimeStamp;
  STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR;

typedef struct _M_PEB_LDR_DATA   /* Size=0x58 */
{
    /* 0x0000 */ uint32_t Length;
    /* 0x0004 */ unsigned char Initialized;
    unsigned char Padding[3];
    /* 0x0008 */ void* SsHandle;
    /* 0x0010 */ LIST_ENTRY InLoadOrderModuleList;
    /* 0x0020 */ LIST_ENTRY InMemoryOrderModuleList;
    /* 0x0030 */ LIST_ENTRY InInitializationOrderModuleList;
    /* 0x0040 */ void* EntryInProgress;
    /* 0x0048 */ unsigned char ShutdownInProgress;
    unsigned char Padding2[3];
    /* 0x0050 */ void* ShutdownThreadId;
} M_PEB_LDR_DATA, *PM_PEB_LDR_DATA;

struct _M_RTL_CRITICAL_SECTION;
typedef struct _M_RTL_CRITICAL_SECTION M_RTL_CRITICAL_SECTION, *PM_RTL_CRITICAL_SECTION;

typedef struct _M_RTL_CRITICAL_SECTION_DEBUG   /* Size=0x30 */
{
    /* 0x0000 */ uint16_t Type;
    /* 0x0002 */ uint16_t CreatorBackTraceIndex;
    uint32_t Padding;
    /* 0x0008 */ M_RTL_CRITICAL_SECTION* CriticalSection;
    /* 0x0010 */ LIST_ENTRY ProcessLocksList;
    /* 0x0020 */ uint32_t EntryCount;
    /* 0x0024 */ uint32_t ContentionCount;
    /* 0x0028 */ uint32_t Flags;
    /* 0x002c */ uint16_t CreatorBackTraceIndexHigh;
    /* 0x002e */ uint16_t SpareUSHORT;
} M_RTL_CRITICAL_SECTION_DEBUG, *PM_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _M_RTL_CRITICAL_SECTION   /* Size=0x28 */
{
    /* 0x0000 */ M_RTL_CRITICAL_SECTION_DEBUG* DebugInfo;
    /* 0x0008 */ int32_t LockCount;
    /* 0x000c */ int32_t RecursionCount;
    /* 0x0010 */ void* OwningThread;
    /* 0x0018 */ void* LockSemaphore;
    /* 0x0020 */ uint64_t SpinCount;
} M_RTL_CRITICAL_SECTION, *PM_RTL_CRITICAL_SECTION;

typedef struct _LEAP_SECOND_DATA   /* Size=0x10 */
{
    /* 0x0000 */ unsigned char Enabled;
    /* 0x0004 */ uint32_t Count;
    /* 0x0008 */ LARGE_INTEGER Data[1];
} LEAP_SECOND_DATA, *PLEAP_SECOND_DATA;

typedef struct _M_RTL_USER_PROCESS_PARAMETERS {
  unsigned int MaximumLength;
  unsigned int Length;
  unsigned int Flags;
  unsigned int DebugFlags;
  void *ConsoleHandle;
  unsigned int ConsoleFlags;
  void *StandardInput;
  void *StandardOutput;
  void *StandardError;
  CURDIR CurrentDirectory;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  void *Environment;
  unsigned int StartingX;
  unsigned int StartingY;
  unsigned int CountX;
  unsigned int CountY;
  unsigned int CountCharsX;
  unsigned int CountCharsY;
  unsigned int FillAttribute;
  unsigned int WindowFlags;
  unsigned int ShowWindowFlags;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING DesktopInfo;
  UNICODE_STRING ShellInfo;
  UNICODE_STRING RuntimeData;
  RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
  UINT64 EnvironmentSize;
  UINT64 EnvironmentVersion;
  void *PackageDependencyData;
  unsigned int ProcessGroupId;
  unsigned int LoaderThreads;
  UNICODE_STRING RedirectionDllName;
  UNICODE_STRING HeapPartitionName;
  UINT64 *DefaultThreadpoolCpuSetMasks;
  unsigned int DefaultThreadpoolCpuSetMaskCount;
  unsigned int DefaultThreadpoolThreadMaximum;
} M_RTL_USER_PROCESS_PARAMETERS, *PM_RTL_USER_PROCESS_PARAMETERS;

typedef struct _M_PEB   /* Size=0x7c8 */
{
    /* 0x0000 */ unsigned char InheritedAddressSpace;
    /* 0x0001 */ unsigned char ReadImageFileExecOptions;
    /* 0x0002 */ unsigned char BeingDebugged;
    /* 0x0003 */ unsigned char BitFieldFlags;
    /* 0x0004 */ unsigned char Padding0[4];
    /* 0x0008 */ void* Mutant;
    /* 0x0010 */ void* ImageBaseAddress;
    /* 0x0018 */ M_PEB_LDR_DATA* Ldr;
    /* 0x0020 */ M_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    /* 0x0028 */ void* SubSystemData;
    /* 0x0030 */ void* ProcessHeap;
    /* 0x0038 */ M_RTL_CRITICAL_SECTION* FastPebLock;
    /* 0x0040 */ SLIST_HEADER* AtlThunkSListPtr;
    /* 0x0048 */ void* IFEOKey;
    /* 0x0050 */ uint32_t CrossProcessFlags;
    /* 0x0054 */ unsigned char Padding1[4];
    /* 0x0058 */ void* KernelCallbackTable;
    /* 0x0060 */ uint32_t SystemReserved;
    /* 0x0064 */ uint32_t AtlThunkSListPtr32;
    /* 0x0068 */ void* ApiSetMap;
    /* 0x0070 */ uint32_t TlsExpansionCounter;
    /* 0x0074 */ unsigned char Padding2[4];
    /* 0x0078 */ void* TlsBitmap;
    /* 0x0080 */ uint32_t TlsBitmapBits[2];
    /* 0x0088 */ void* ReadOnlySharedMemoryBase;
    /* 0x0090 */ void* SharedData;
    /* 0x0098 */ void** ReadOnlyStaticServerData;
    /* 0x00a0 */ void* AnsiCodePageData;
    /* 0x00a8 */ void* OemCodePageData;
    /* 0x00b0 */ void* UnicodeCaseTableData;
    /* 0x00b8 */ uint32_t NumberOfProcessors;
    /* 0x00bc */ uint32_t NtGlobalFlag;
    /* 0x00c0 */ LARGE_INTEGER CriticalSectionTimeout;
    /* 0x00c8 */ uint64_t HeapSegmentReserve;
    /* 0x00d0 */ uint64_t HeapSegmentCommit;
    /* 0x00d8 */ uint64_t HeapDeCommitTotalFreeThreshold;
    /* 0x00e0 */ uint64_t HeapDeCommitFreeBlockThreshold;
    /* 0x00e8 */ uint32_t NumberOfHeaps;
    /* 0x00ec */ uint32_t MaximumNumberOfHeaps;
    /* 0x00f0 */ void** ProcessHeaps;
    /* 0x00f8 */ void* GdiSharedHandleTable;
    /* 0x0100 */ void* ProcessStarterHelper;
    /* 0x0108 */ uint32_t GdiDCAttributeList;
    /* 0x010c */ unsigned char Padding3[4];
    /* 0x0110 */ M_RTL_CRITICAL_SECTION* LoaderLock;
    /* 0x0118 */ uint32_t OSMajorVersion;
    /* 0x011c */ uint32_t OSMinorVersion;
    /* 0x0120 */ uint16_t OSBuildNumber;
    /* 0x0122 */ uint16_t OSCSDVersion;
    /* 0x0124 */ uint32_t OSPlatformId;
    /* 0x0128 */ uint32_t ImageSubsystem;
    /* 0x012c */ uint32_t ImageSubsystemMajorVersion;
    /* 0x0130 */ uint32_t ImageSubsystemMinorVersion;
    /* 0x0134 */ unsigned char Padding4[4];
    /* 0x0138 */ uint64_t ActiveProcessAffinityMask;
    /* 0x0140 */ uint32_t GdiHandleBuffer[60];
    /* 0x0230 */ void* PostProcessInitRoutine;
    /* 0x0238 */ void* TlsExpansionBitmap;
    /* 0x0240 */ uint32_t TlsExpansionBitmapBits[32];
    /* 0x02c0 */ uint32_t SessionId;
    /* 0x02c4 */ unsigned char Padding5[4];
    /* 0x02c8 */ ULARGE_INTEGER AppCompatFlags;
    /* 0x02d0 */ ULARGE_INTEGER AppCompatFlagsUser;
    /* 0x02d8 */ void* pShimData;
    /* 0x02e0 */ void* AppCompatInfo;
    /* 0x02e8 */ UNICODE_STRING CSDVersion;
    /* 0x02f8 */ void* ActivationContextData;
    /* 0x0300 */ void* ProcessAssemblyStorageMap;
    /* 0x0308 */ void* SystemDefaultActivationContextData;
    /* 0x0310 */ void* SystemAssemblyStorageMap;
    /* 0x0318 */ uint64_t MinimumStackCommit;
    /* 0x0320 */ void* SparePointers[4];
    /* 0x0340 */ uint32_t SpareUlongs[5];
    uint32_t PaddingSpareUlongs;
    /* 0x0358 */ void* WerRegistrationData;
    /* 0x0360 */ void* WerShipAssertPtr;
    /* 0x0368 */ void* pUnused;
    /* 0x0370 */ void* pImageHeaderHash;
    /* 0x0378 */ uint32_t TracingFlags;
    /* 0x037c */ unsigned char Padding6[4];
    /* 0x0380 */ uint64_t CsrServerReadOnlySharedMemoryBase;
    /* 0x0388 */ uint64_t TppWorkerpListLock;
    /* 0x0390 */ LIST_ENTRY TppWorkerpList;
    /* 0x03a0 */ void* WaitOnAddressHashTable[128];
    /* 0x07a0 */ void* TelemetryCoverageHeader;
    /* 0x07a8 */ uint32_t CloudFileFlags;
    /* 0x07ac */ uint32_t CloudFileDiagFlags;
    /* 0x07b0 */ char PlaceholderCompatibilityMode;
    /* 0x07b1 */ char PlaceholderCompatibilityModeReserved[7];
    /* 0x07b8 */ LEAP_SECOND_DATA* LeapSecondData;
    /* 0x07c0 */ uint32_t LeapSecondFlags;
    /* 0x07c4 */ uint32_t NtGlobalFlag2;
} M_PEB, *PM_PEB;

#endif