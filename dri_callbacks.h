#ifndef CALLBACKS_H
#define CALLBACKS_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <stdint.h>
#include <ntifs.h>
#include "dri_stringset.h"
#include "dri_ullset.h"

#define PRIVILEGE_OFFSET 0x40
#define IMAGE_FILE_PTR_TO_IMAGE_NAME_OFFSET 0x8
#define ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET 0x160
#define ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET_BEFORE_1903 0x168
#define PROTECTION_OFFSET_AFTER_26100 0x5FA
#define PROTECTION_OFFSET_AFTER_19041 0x87A
#define PROTECTION_OFFSET_AFTER_18362 0x6FA
#define PROTECTION_OFFSET_BEFORE_18362 0x6CA

extern int SeAuditProcessCreationInfoOffset;
extern int ActiveProcessLinksOffset;
extern int ImageFilePointerOffset;
extern int ProtectionOffset;
extern POBJECT_TYPE EtwConsumerObjectType;
extern POBJECT_TYPE EtwSessionObjectType;

extern UCHAR *PsGetProcessImageFileName(PEPROCESS EProcess);
extern NTSTATUS SeLocateProcessImageName(PEPROCESS Process, PUNICODE_STRING *pImageFileName);
extern PPEB PsGetProcessPeb(PEPROCESS Process);
extern NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID *Object);
extern POBJECT_TYPE ObGetObjectType(IN PVOID Object);

extern StringSet ProtectProcessSet;
extern StringSet WhiteListSet;
extern StringSet BlackListSet;
extern ULLSet ProtectedPidSet;
extern ULLSet ProtectedListEntrySet;

extern PVOID GlobalPsObCallbackHandle;
extern PVOID GlobalEtwConsumerCallbackHandle;

NTSTATUS CallbacksInit();
NTSTATUS CallbacksResume();
NTSTATUS InitEtwObjectTypes();
NTSTATUS InitSeAuditOffset();
// 打开进程回调
OB_PREOP_CALLBACK_STATUS PreOpenObjectCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);
// Etw 对象回调
OB_PREOP_CALLBACK_STATUS PreEtwObjectCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);
// 创建进程回调
VOID CreateProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);

#define KSLEEP(MiliSeconds) do { LARGE_INTEGER __li = {0}; __li.QuadPart = -10 * (MiliSeconds) * 1000; KeDelayExecutionThread(KernelMode, FALSE, &(__li)); } while(0)

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO {
    OBJECT_NAME_INFORMATION *ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _SEP_TOKEN_PRIVILEGES {
  ULONGLONG Present;
  ULONGLONG Enabled;
  ULONGLONG EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;

typedef union _PS_PROTECTION
{
	UCHAR Level;
	struct
	{
		int Type : 3;
		int Audit : 1;
		int Signer : 4;
	} Flags;
} PS_PROTECTION, *PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode = 1,
	PsProtectedSignerCodeGen = 2,
	PsProtectedSignerAntimalware = 3,
	PsProtectedSignerLsa = 4,
	PsProtectedSignerWindows = 5,
	PsProtectedSignerWinTcb = 6,
	PsProtectedSignerMax = 7
} PS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2,
	PsProtectedTypeMax = 3

} PS_PROTECTED_TYPE;

#endif // CALLBACKS_H