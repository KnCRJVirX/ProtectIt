#include "protectordef.h"
#include "dri_callbacks.h"
#include "dri_protector.h"
#include "dri_notify.h"

StringSet ProtectProcessSet;
StringSet WhiteListSet;
StringSet BlackListSet;
ULLSet ProtectedPidSet;
ULLSet ProtectedListEntrySet;

PVOID GlobalPsObCallbackHandle = NULL;
PVOID GlobalEtwConsumerCallbackHandle = NULL;

int SeAuditProcessCreationInfoOffset = 0;
int ActiveProcessLinksOffset = 0;
int ImageFilePointerOffset = 0;
int ProtectionOffset = 0;
POBJECT_TYPE EtwConsumerObjectType = NULL;
POBJECT_TYPE EtwSessionObjectType = NULL;

static UNICODE_STRING GetFileNameFromFullPath(PCUNICODE_STRING FullPath) {
    UNICODE_STRING tmpFileName;
    tmpFileName.Buffer = FullPath->Buffer;
    tmpFileName.Length = FullPath->Length;;
    tmpFileName.MaximumLength = FullPath->MaximumLength;

    // 从尾部向前扫描
    for (USHORT i = FullPath->Length / sizeof(WCHAR); i > 0; i--)
    {
        if (FullPath->Buffer[i - 1] == L'\\')
        {
            tmpFileName.Buffer = &FullPath->Buffer[i];
            tmpFileName.Length = FullPath->Length - i * sizeof(WCHAR);
            break;
        }
    }

    // 手动构造UNICODE_STRING返回
    UNICODE_STRING result = {0};
    result.MaximumLength = tmpFileName.Length + sizeof(WCHAR);
    result.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, result.MaximumLength, 'File');
    if (result.Buffer)
    {
        // 清零内存
        RtlZeroMemory(result.Buffer, result.MaximumLength);
        // 仅复制实际长度的数据
        RtlCopyMemory(result.Buffer, tmpFileName.Buffer, tmpFileName.Length);
        // 设置长度
        result.Length = tmpFileName.Length;
    }

    return result;
}

static UNICODE_STRING GetProcessImageFileName(PEPROCESS Process, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo) {
        PCUNICODE_STRING pcPath = CreateInfo->ImageFileName;
        UNICODE_STRING fileName = GetFileNameFromFullPath(pcPath);
        return fileName;
    } else {
        PUNICODE_STRING pPath = NULL;
        SeLocateProcessImageName(Process, &pPath);
        UNICODE_STRING fileName = GetFileNameFromFullPath(pPath);
        ExFreePool(pPath);
        return fileName;
    }
}

NTSTATUS CallbacksInit() {
    NTSTATUS status = 0;

    // 初始化列表集合
    StringSetInit(&ProtectProcessSet);
    StringSetInit(&WhiteListSet);
    StringSetInit(&BlackListSet);
    ULLSetInit(&ProtectedPidSet);
    ULLSetInit(&ProtectedListEntrySet);

    // 初始化 SeAuditProcessCreationInfo 偏移量
    InitSeAuditOffset();

    // 获取系统版本
    RTL_OSVERSIONINFOW verInfo = { 0 };
    verInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

    // 初始化版本有关偏移量
    PEPROCESS pCurrent = PsGetCurrentProcess();
    PUCHAR pImageFileName = PsGetProcessImageFileName(pCurrent);
    if (verInfo.dwMajorVersion >= 10) {
        // ActiveProcessLinks
        if (verInfo.dwBuildNumber < 18362) {
            ActiveProcessLinksOffset = (int)((PCHAR)(pImageFileName) - ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET_BEFORE_1903 - (PCHAR)pCurrent);
        } else {
            ActiveProcessLinksOffset = (int)((PCHAR)(pImageFileName) - ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET - (PCHAR)pCurrent);
        }
        DbgPrint("Protector: ActiveProcessLinksOffset = 0x%X\n", ActiveProcessLinksOffset);

        // Protection
        if (verInfo.dwBuildNumber >= 26100) {
            ProtectionOffset = PROTECTION_OFFSET_AFTER_26100;
        } else if (verInfo.dwBuildNumber >= 19041) {
            ProtectionOffset = PROTECTION_OFFSET_AFTER_19041;
        } else if (verInfo.dwBuildNumber >= 18362) {
            ProtectionOffset = PROTECTION_OFFSET_AFTER_18362;
        } else {
            ProtectionOffset = PROTECTION_OFFSET_BEFORE_18362;
        }
        DbgPrint("Protector: ProtectionOffset = 0x%X\n", ProtectionOffset);
    } else {
        DbgPrint("Protector: Unsupported OS version for ActiveProcessLinksOffset calculation.\n");
    }

    // 初始化 ImageFilePointer 偏移量
    ImageFilePointerOffset = (int)((PCHAR)(pImageFileName) - IMAGE_FILE_PTR_TO_IMAGE_NAME_OFFSET - (PCHAR)pCurrent);
    DbgPrint("Protector: ImageFilePointerOffset = 0x%X\n", ImageFilePointerOffset);

    // 注册打开进程回调
    // 准备回调注册结构体
    OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
    OB_OPERATION_REGISTRATION processOperation = { 0 };
    OB_OPERATION_REGISTRATION threadOperation = { 0 };
    // Altitude 是一个字符串，决定回调的优先级。数字越大优先级越高。
    // 微软规定了一套 Altitude 分配规则，自己测试随便写一个唯一的数字字符串即可。
    UNICODE_STRING altitude1 = RTL_CONSTANT_STRING(L"321000");
    // 设置进程回调
    processOperation.ObjectType = PsProcessType; // 监控进程对象
    processOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    processOperation.PreOperation = PreOpenObjectCallback; // 设置 Pre 回调
    processOperation.PostOperation = NULL; // 不需要 Post 回调
    // 设置线程回调
    threadOperation.ObjectType = PsThreadType; // 监控线程对象
    threadOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    threadOperation.PreOperation = PreOpenObjectCallback; // 设置 Pre 回调
    threadOperation.PostOperation = NULL; // 不需要 Post 回调
    // 设置回调注册结构体
    OB_OPERATION_REGISTRATION operations[] = { processOperation, threadOperation };
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.Altitude = altitude1;
    callbackRegistration.RegistrationContext = NULL;
    callbackRegistration.OperationRegistration = operations;
    // 注册回调
    status = ObRegisterCallbacks(&callbackRegistration, &GlobalPsObCallbackHandle);
    if (NT_SUCCESS(status)) {
        DbgPrint("Protector: ObRegisterCallbacks succeeded.\n");
    } else {
        return status;
    }

    // 注册创建进程回调
    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, FALSE);
    if (NT_SUCCESS(status)) {
        DbgPrint("Protector: CreateProcessNotifyCallback succeeded.\n");
    } else {
        return status;
    }

    // 设置白名单
    StringSetInsert(&WhiteListSet, L"System");
    StringSetInsert(&WhiteListSet, L"smss.exe");
    StringSetInsert(&WhiteListSet, L"csrss.exe");
    StringSetInsert(&WhiteListSet, L"lsass.exe");
    StringSetInsert(&WhiteListSet, L"dwm.exe");
    StringSetInsert(&WhiteListSet, L"explorer.exe");
    StringSetInsert(&WhiteListSet, L"svchost.exe");
    StringSetInsert(&WhiteListSet, L"ctfmon.exe");

    return STATUS_SUCCESS;
}

NTSTATUS CallbacksResume() {
    // 注销创建进程回调
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);
    // 注销对象管理回调
    if (GlobalPsObCallbackHandle) {
        ObUnRegisterCallbacks(GlobalPsObCallbackHandle);
        GlobalPsObCallbackHandle = NULL;
    }
    if (GlobalEtwConsumerCallbackHandle) {
        ObUnRegisterCallbacks(GlobalEtwConsumerCallbackHandle);
        GlobalEtwConsumerCallbackHandle = NULL;
    }

    return STATUS_SUCCESS;
}
NTSTATUS InitSeAuditOffset()
{
    PEPROCESS pProcess = NULL;
    NTSTATUS status;
    BOOLEAN foundCsrss = FALSE;

    DbgPrint("Protector: Searching for csrss.exe to calculate offsets...\n");

    // 遍历 PID 寻找 csrss.exe
    // csrss 通常在较小的 PID 范围内，遍历到 10000 足够了
    for (ULONG i = 4; i < 10000; i += 4) 
    {
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)i, &pProcess);
        if (!NT_SUCCESS(status)) continue;

        // 获取短名字 (ImageFileName)
        PUCHAR procName = PsGetProcessImageFileName(pProcess);
        if (procName) {
            DbgPrint("Protector: PID %d Name: %s\n", i, procName);
        }

        // 检查是不是 csrss.exe (忽略大小写比较略去，系统进程通常是小写)
        if (procName && _stricmp((char*)procName, "csrss.exe") == 0) 
        {
            DbgPrint("Protector: Found csrss.exe at PID %d (EPROCESS: 0x%p)\n", i, pProcess);
            foundCsrss = TRUE;

            // 获取完整路径名
            PUNICODE_STRING pImageName = NULL;
            status = SeLocateProcessImageName(pProcess, &pImageName);
            DbgPrint("Protector: Full Image Path: %wZ\n", pImageName);
            
            // 开始在 csrss.exe 的 EPROCESS 里扫描
            ULONG_PTR pBase = (ULONG_PTR)pProcess;
            
            for (ULONG offset = 0; offset < 0x1000; offset += sizeof(PVOID)) 
            {
                ULONG_PTR val = *(ULONG_PTR*)(pBase + offset);
                // 过滤非内核地址
                if (val < 0xFFFF000000000000) {
                    continue;
                }

                POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)val;

                __try {
                    if (MmIsAddressValid(pNameInfo) && 
                        MmIsAddressValid(pNameInfo->Name.Buffer)) 
                    {
                        // 直接比较
                        if (RtlCompareUnicodeString(&pNameInfo->Name, pImageName, TRUE) == 0) 
                        {
                            SeAuditProcessCreationInfoOffset = offset;
                            DbgPrint("Protector: SeAuditProcessCreationInfo Offset = 0x%X\n", offset);
                            DbgPrint("Protector: Path Content = %wZ\n", &pNameInfo->Name);
                            
                            // 找到后解引用并退出
                            ExFreePool(pImageName);
                            ObDereferenceObject(pProcess);
                            return STATUS_SUCCESS;
                        }
                    }
                }
                __except (1) { continue; }
            }
        }

        // 记得释放引用
        ObDereferenceObject(pProcess);

        if (SeAuditProcessCreationInfoOffset != 0) break; // 找到了就退出循环
    }

    if (SeAuditProcessCreationInfoOffset == 0) {
        DbgPrint("Protector: [FAILED] Could not find csrss.exe or offset.\n");
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS PreOpenObjectCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    // 发起操作的进程
    PEPROCESS currentProcess = PsGetCurrentProcess();

    // 不拦截System进程
    if (currentProcess == PsInitialSystemProcess) {
        return OB_PREOP_SUCCESS;
    }

    // 不拦截白名单进程的打开操作
    UNICODE_STRING currentName = GetProcessImageFileName(currentProcess, NULL);
    if (StringSetContains(&WhiteListSet, currentName.Buffer)) {
        goto End;
    }

    // 不拦截保护进程互相打开操作
    if (ULLSetContains(&ProtectedPidSet, (ULONG_PTR)PsGetProcessId(currentProcess))) {
        goto End;
    }

    PEPROCESS targetProcess = NULL;
    if (OperationInformation->ObjectType == *PsProcessType) {
        // 被打开的进程
        targetProcess = (PEPROCESS)OperationInformation->Object;
        // 不拦截对自己的打开
        if (targetProcess == currentProcess) {
            goto End;
        }
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        // 被打开的线程
        PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
        targetProcess = PsGetThreadProcess(targetThread);
        // 不拦截对自己的打开
        if (targetProcess == currentProcess) {
            goto End;
        }
    } else {
        // 其他对象类型不处理
        goto End;
    }

    // 拦截受保护进程的打开操作
    if (ULLSetContains(&ProtectedPidSet, (ULONG_PTR)PsGetProcessId(targetProcess))) {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            // 拦截创建句柄
            // 清空权限
            OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

            // 调试信息
#ifdef _DEBUG
            ULONG pid = HandleToUlong(PsGetProcessId(targetProcess));
            ULONG currentPid = HandleToUlong(PsGetProcessId(currentProcess));
            DbgPrint("Protector: Blocked handle open. TargetPID: %lu, By: %wZ (PID: %lu)\n", pid, &currentName, currentPid);
#endif
        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            // 拦截复制句柄
            // 清空权限
            OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

            // 调试信息
#ifdef _DEBUG
            ULONG pid = HandleToUlong(PsGetProcessId(targetProcess));
            ULONG currentPid = HandleToUlong(PsGetProcessId(currentProcess));
            DbgPrint("Protector: Blocked handle duplicate. TargetPID: %lu, By: %wZ (PID: %lu)\n", pid, &currentName, currentPid);
#endif
        }
    }

End:
    RtlFreeUnicodeString(&currentName);
    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS PreEtwObjectCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    // 检查是否是 EtwConsumer 对象
    if (OperationInformation->ObjectType == EtwConsumerObjectType) {
        // 检查发起者是否是黑名单进程
        PEPROCESS CurrentProcess = PsGetCurrentProcess();
        UNICODE_STRING processName = GetProcessImageFileName(CurrentProcess, NULL);
        if (StringSetContains(&BlackListSet, processName.Buffer)) {
            // 剥夺权限
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

            // 调试信息
            DbgPrint("Protector: Blocked ETW Consumer access from %wZ (PID: %lu)\n", &processName, HandleToUlong(PsGetProcessId(CurrentProcess)));
        }
        RtlFreeUnicodeString(&processName);
    }
    
    // 同样逻辑处理 EtwSessionDemuxEntry，防止它 StartTrace
    if (OperationInformation->ObjectType == EtwSessionObjectType) {
        PEPROCESS CurrentProcess = PsGetCurrentProcess();
        UNICODE_STRING processName = GetProcessImageFileName(CurrentProcess, NULL);
        if (StringSetContains(&BlackListSet, processName.Buffer)) {
            // 剥夺权限
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

            // 调试信息
            DbgPrint("Protector: Blocked ETW Session Control from %wZ (PID: %lu)\n", &processName, HandleToUlong(PsGetProcessId(CurrentProcess)));
        }
        RtlFreeUnicodeString(&processName);
    }

    return OB_PREOP_SUCCESS;
}

// 移除进程权限
VOID RemoveProcessPrivileges(PEPROCESS Process)
{
    const ULONG removePrivileges[] = { SE_DEBUG_PRIVILEGE, 
                                       SE_SECURITY_PRIVILEGE, 
                                       SE_SYSTEM_PROFILE_PRIVILEGE,
                                       SE_IMPERSONATE_PRIVILEGE,
                                       SE_BACKUP_PRIVILEGE, 
                                       SE_AUDIT_PRIVILEGE, 
                                       SE_LOAD_DRIVER_PRIVILEGE, 
                                       SE_TCB_PRIVILEGE, 
                                       SE_PROF_SINGLE_PROCESS_PRIVILEGE };
    const SIZE_T privilegesCount = sizeof(removePrivileges) / sizeof(removePrivileges[0]);

    // 获取进程的 Token 对象
    PACCESS_TOKEN token = PsReferencePrimaryToken(Process);
    if (!token) {
        return;
    }

    // 取到指向Privileges的指针
    PSEP_TOKEN_PRIVILEGES pPrivileges = (PSEP_TOKEN_PRIVILEGES)((PUCHAR)token + PRIVILEGE_OFFSET);

    // 检查指针有效性
    if (!MmIsAddressValid(pPrivileges)) {
        ObDereferenceObject(token);
        return;
    }

    // 准备移除权限的掩码
    ULONGLONG removeMask = 0;
    for (SIZE_T i = 0; i < privilegesCount; i++) {
        removeMask |= (1ULL << removePrivileges[i]);
    }

    // 移除指定权限
    pPrivileges->Enabled &= ~removeMask;
    pPrivileges->Present &= ~removeMask;
    pPrivileges->EnabledByDefault &= ~removeMask;

    // 调试信息
#ifdef _DEBUG
    DbgPrint("Protector: Removed privileges 0x%llX from process PID: %lu\n", removeMask, HandleToUlong(PsGetProcessId(Process)));
#endif

    ObDereferenceObject(token);
}

// 用于修改进程名的工作项上下文结构体
typedef struct _PROCESS_INFO_CONTEXT {
    HANDLE ProcessId;
    PIO_WORKITEM WorkItem;
} PROCESS_INFO_CONTEXT, *PPROCESS_INFO_CONTEXT;

// 延迟修改
VOID DelayModifyProcessRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    KSLEEP(1000);
    PPROCESS_INFO_CONTEXT pContext = (PPROCESS_INFO_CONTEXT)Context;
    HANDLE processId = pContext->ProcessId;
    PEPROCESS Process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(processId, &Process))) {
        // 改PPL
        PPS_PROTECTION pPPL = (PPS_PROTECTION)((PUCHAR)Process + ProtectionOffset);
        PS_PROTECTION ppl = {0};
        ppl.Flags.Type = PsProtectedTypeProtectedLight;
        ppl.Flags.Signer = PsProtectedSignerWinTcb;
        pPPL->Level = ppl.Level;
        // 调试信息
#ifdef _DEBUG
        DbgPrint("Protector: Modify PID: %d Protection to: 0x%X\n", processId, pPPL->Level);
#endif

        // 释放工作项和上下文
        IoFreeWorkItem(pContext->WorkItem);
        ExFreePoolWithTag(pContext, 'Work');
        ObDereferenceObject(Process);
    }
}

VOID HideAndModifyProcess(PEPROCESS Process) {
    // 修改进程名
    PUCHAR psName = PsGetProcessImageFileName(Process);
    RtlCopyMemory(psName, FAKE_PROCESS_NAME, sizeof(FAKE_PROCESS_NAME));
    // 调试信息
#ifdef _DEBUG
    DbgPrint("Protector: Modified process name to: %s\n", psName);
#endif

    // 修改进程路径
    PSE_AUDIT_PROCESS_CREATION_INFO pSeAuditInfo = (PSE_AUDIT_PROCESS_CREATION_INFO)((PUCHAR)Process + SeAuditProcessCreationInfoOffset);
    if (pSeAuditInfo->ImageFileName->Name.Buffer && pSeAuditInfo->ImageFileName->Name.Length >= sizeof(FAKE_PROCESS_NTPATH_W)) {
        UNICODE_STRING fakeImagePath;
        RtlInitUnicodeString(&fakeImagePath, FAKE_PROCESS_NTPATH_W);
        
        PWCH pathBuffer = pSeAuditInfo->ImageFileName->Name.Buffer;
        RtlCopyMemory(pathBuffer, fakeImagePath.Buffer, fakeImagePath.Length + sizeof(WCHAR));
        pSeAuditInfo->ImageFileName->Name.Length = fakeImagePath.Length;

        // 调试信息
#ifdef _DEBUG
        DbgPrint("Protector: Modified process path to: %wZ\n", &pSeAuditInfo->ImageFileName->Name);
#endif
    }

    // 修改 ImageFilePointer 中的路径
    PFILE_OBJECT pFileObject = *(PFILE_OBJECT*)((PUCHAR)Process + ImageFilePointerOffset);
    if (pFileObject) {
        UNICODE_STRING fakeFileObjPath;
        RtlInitUnicodeString(&fakeFileObjPath, FAKE_PROCESS_FILEOBJECT_FILENAME_W);

        RtlCopyMemory(pFileObject->FileName.Buffer, fakeFileObjPath.Buffer, fakeFileObjPath.Length + sizeof(WCHAR));
        pFileObject->FileName.Length = fakeFileObjPath.Length;

        // 调试信息
#ifdef _DEBUG
        DbgPrint("Protector: Modified ImageFilePointer path to: %wZ\n", &pFileObject->FileName);
#endif
    }
}

// 修改新黑名单进程
VOID ModifyBlacklistedProcess(PEPROCESS Process)
{
    // 移除权限
    RemoveProcessPrivileges(Process);
    // 调试信息
#ifdef _DEBUG
    DbgPrint("Protector: Modified blacklisted process PID: %lu\n", PsGetProcessId(Process));
#endif
}

// 创建进程回调
VOID CreateProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    if (CreateInfo) {
        // 获取镜像文件名
        UNICODE_STRING processName = GetProcessImageFileName(Process, CreateInfo);

        if (StringSetContains(&ProtectProcessSet, processName.Buffer)) {
            // 保护进程
            // 调试信息
#ifdef _DEBUG
        DbgPrint("Protector: Protected process created: %wZ (PID: %lu, Parent PID: %lu)\n", &processName, ProcessId, CreateInfo->ParentProcessId);
#endif
            // 加入保护 PID 集合
            ULLSetInsert(&ProtectedPidSet, (ULONG_PTR)ProcessId);
            // 修改进程
            HideAndModifyProcess(Process);

            // 分配上下文
            PROCESS_INFO_CONTEXT* pContext = (PROCESS_INFO_CONTEXT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_INFO_CONTEXT), 'Work');
            if (pContext) {
                pContext->ProcessId = ProcessId;
                pContext->WorkItem = IoAllocateWorkItem(GlobalDriverObject->DeviceObject);
                if (pContext->WorkItem) {
                    // 投递工作项
                    IoQueueWorkItem(pContext->WorkItem, DelayModifyProcessRoutine, CriticalWorkQueue, pContext);
                } else {
                    ExFreePoolWithTag(pContext, 'Work');
                }
            }
            
            // 通知
            NotifyCreateProcess(GlobalDriverObject, Process);
        } else if (StringSetContains(&BlackListSet, processName.Buffer)) {
            // 黑名单进程
            // 调试信息
#ifdef _DEBUG
        DbgPrint("Protector: Blacklist process created: %wZ (PID: %lu, Parent PID: %lu)\n", &processName, ProcessId, CreateInfo->ParentProcessId);
#endif
            // 修改进程
            ModifyBlacklistedProcess(Process);
        }

        RtlFreeUnicodeString(&processName);
    } else {
        // 进程退出，移除保护 PID
        if (ULLSetContains(&ProtectedPidSet, (ULONG_PTR)ProcessId)) {
            ULLSetRemove(&ProtectedPidSet, (ULONG_PTR)ProcessId);
            
            // 调试信息
#ifdef _DEBUG
            DbgPrint("Protector: Protected process exited. PID: %lu\n", ProcessId);
#endif
        }
    }
}