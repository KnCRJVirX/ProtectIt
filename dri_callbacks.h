#ifndef CALLBACKS_H
#define CALLBACKS_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <ntifs.h>
#include "dri_stringset.h"
#include "dri_ullset.h"

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO {
    OBJECT_NAME_INFORMATION *ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _SEP_TOKEN_PRIVILEGES {
  ULONGLONG Present;
  ULONGLONG Enabled;
  ULONGLONG EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;

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

typedef struct _RTL_USER_PROCESS_PARAMETERS {
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
} RTL_USER_PROCESS_PARAMETERS;

#define PRIVILEGE_OFFSET 0x40
#define ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET 0x160
#define ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET_BEFORE_1903 0x168
#define PEB_PROCESS_PARAMETERS_OFFSET 0x20
extern int SeAuditProcessCreationInfoOffset;
extern int ActiveProcessLinksOffset;

extern UCHAR *PsGetProcessImageFileName(PEPROCESS EProcess);
extern NTSTATUS SeLocateProcessImageName(PEPROCESS Process, PUNICODE_STRING *pImageFileName);
extern PPEB PsGetProcessPeb(PEPROCESS Process);

extern StringSet ProtectProcessSet;
extern StringSet WhiteListSet;
extern StringSet BlackListSet;
extern ULLSet ProtectedPidSet;
extern ULLSet ProtectedListEntrySet;

NTSTATUS CallbacksInit();
NTSTATUS CallbacksResume();
// 初始化 SeAuditProcessCreationInfo 偏移量
NTSTATUS InitSeAuditOffset();
// 打开进程回调
OB_PREOP_CALLBACK_STATUS PreOpenProcessCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);
// 创建进程回调
VOID CreateProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);

#endif // CALLBACKS_H