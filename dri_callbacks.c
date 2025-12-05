#include "protectordef.h"
#include "dri_callbacks.h"
#include "dri_protector.h"

StringSet ProtectProcessSet;
StringSet WhiteListSet;
StringSet BlackListSet;
ULLSet ProtectedPidSet;
ULLSet ProtectedListEntrySet;

int SeAuditProcessCreationInfoOffset = 0;
int ActiveProcessLinksOffset = 0;

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

    // 初始化 ActiveProcessLinks 偏移量
    PEPROCESS pCurrent = PsGetCurrentProcess();
    PUCHAR pImageFileName = PsGetProcessImageFileName(pCurrent);
    if (verInfo.dwMajorVersion >= 10) {
        if (verInfo.dwBuildNumber < 18362) {
            ActiveProcessLinksOffset = (int)((PCHAR)(pImageFileName) - ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET_BEFORE_1903 - (PCHAR)pCurrent);
        } else {
            ActiveProcessLinksOffset = (int)((PCHAR)(pImageFileName) - ACTIVE_PS_LINKS_TO_IMAGE_NAME_OFFSET - (PCHAR)pCurrent);
        }
        DbgPrint("Protector: ActiveProcessLinksOffset = 0x%X\n", ActiveProcessLinksOffset);
    } else {
        DbgPrint("Protector: Unsupported OS version for ActiveProcessLinksOffset calculation.\n");
    }

    // 注册打开进程回调
    // 准备回调注册结构体
    OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
    OB_OPERATION_REGISTRATION operationRegistration = { 0 };
    // Altitude 是一个字符串，决定回调的优先级。数字越大优先级越高。
    // 微软规定了一套 Altitude 分配规则，自己测试随便写一个唯一的数字字符串即可。
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"321000");
    // 设置我们要监控的操作类型
    // 设置在打开进程类型对象前的回调
    operationRegistration.ObjectType = PsProcessType; // 监控进程对象
    operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration.PreOperation = PreOpenProcessCallback; // 设置 Pre 回调
    operationRegistration.PostOperation = NULL; // 不需要 Post 回调
    // 设置回调注册结构体
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = NULL;
    callbackRegistration.OperationRegistration = &operationRegistration;
    // 注册回调
    status = ObRegisterCallbacks(&callbackRegistration, &GlobalRegistrationHandle);
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
    StringSetInsert(&WhiteListSet, (PUCHAR)"System");
    StringSetInsert(&WhiteListSet, (PUCHAR)"smss.exe");
    StringSetInsert(&WhiteListSet, (PUCHAR)"csrss.exe");
    StringSetInsert(&WhiteListSet, (PUCHAR)"lsass.exe");
    StringSetInsert(&WhiteListSet, (PUCHAR)"dwm.exe");
    StringSetInsert(&WhiteListSet, (PUCHAR)"explorer.exe");
    StringSetInsert(&WhiteListSet, (PUCHAR)"svchost.exe");

    return STATUS_SUCCESS;
}

NTSTATUS CallbacksResume() {
    // 注销创建进程回调
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);
    // 注销对象管理回调
    if (GlobalRegistrationHandle) {
        ObUnRegisterCallbacks(GlobalRegistrationHandle);
        GlobalRegistrationHandle = NULL;
    }

    // 将断链的进程重新链回
    PLIST_ENTRY activeProcessListEntry = (PLIST_ENTRY)((PUCHAR)PsInitialSystemProcess + ActiveProcessLinksOffset);
    while (!ULLSetIsEmpty(&ProtectedListEntrySet)) {
        PLIST_ENTRY entry = (PLIST_ENTRY)ULLGetFirst(&ProtectedListEntrySet);
        InsertHeadList(activeProcessListEntry, entry);
        ULLSetRemove(&ProtectedListEntrySet, (ULONGLONG)entry);

        // 调试信息
        DbgPrint("Protector: Restored process list entry: 0x%p\n", entry);
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

OB_PREOP_CALLBACK_STATUS PreOpenProcessCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    // 不处理非进程对象
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    // 被打开的进程
    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    
    // 发起操作的进程
    PEPROCESS currentProcess = PsGetCurrentProcess();

    // 不拦截对自己的打开
    if (targetProcess == currentProcess) {
        return OB_PREOP_SUCCESS; 
    }

    // 不拦截System进程
    if (currentProcess == PsInitialSystemProcess) {
        return OB_PREOP_SUCCESS;
    }

    // 不拦截白名单进程的打开操作
    PUCHAR currentName = PsGetProcessImageFileName(currentProcess);
    if (currentName && StringSetContains(&WhiteListSet, (PCHAR)currentName)) {
        return OB_PREOP_SUCCESS;
    }

    // 不拦截保护进程互相打开操作
    if (ULLSetContains(&ProtectedPidSet, (ULONG_PTR)PsGetProcessId(currentProcess))) {
        return OB_PREOP_SUCCESS;
    }

    // 拦截受保护进程的打开操作
    if (ULLSetContains(&ProtectedPidSet, (ULONG_PTR)PsGetProcessId(targetProcess))) {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            // 拦截创建句柄
            // 清空权限
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

            // 调试信息
            ULONG pid = HandleToUlong(PsGetProcessId(targetProcess));
            ULONG currentPid = HandleToUlong(PsGetProcessId(currentProcess));
            DbgPrint("Protector: Blocked process open. TargetPID: %lu, By: %s (PID: %lu)\n", pid, currentName ? (PCHAR)currentName : "Unknown", currentPid);
        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            // 拦截复制句柄
            // 清空权限
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

            // 调试信息
            ULONG pid = HandleToUlong(PsGetProcessId(targetProcess));
            ULONG currentPid = HandleToUlong(PsGetProcessId(currentProcess));
            DbgPrint("Protector: Blocked process handle duplicate. TargetPID: %lu, By: %s (PID: %lu)\n", pid, currentName ? (PCHAR)currentName : "Unknown", currentPid);
        }
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

    ObDereferenceObject(token);
}

// 修改进程的PEB
NTSTATUS ModifyProcessPEB(PEPROCESS Process) {
    // 等待200毫秒
    LARGE_INTEGER interval;
    interval.QuadPart = -200 * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);

    KAPC_STATE ApcState;
    NTSTATUS status = STATUS_SUCCESS;
    
    // 获取 PEB 指针 (这个地址是 User Mode 虚拟地址)
    PPEB pPeb = PsGetProcessPeb(Process);
    if (!pPeb) {
        return STATUS_INVALID_PARAMETER;
    }

    // 挂靠到目标进程 (切换 CR3)
    // 这一步之后，我们就可以像在 Ring3 进程内部一样访问 pPeb 了
    KeStackAttachProcess(Process, &ApcState);

    __try {
        // 获取 ProcessParameters
        RTL_USER_PROCESS_PARAMETERS* pParams = *((RTL_USER_PROCESS_PARAMETERS**)((PUCHAR)pPeb + PEB_PROCESS_PARAMETERS_OFFSET));
        
        // 检查指针是否有效
        if (pParams && pParams->ImagePathName.Buffer) {
            
            // 计算新路径长度
            USHORT newLen = (USHORT)(sizeof(FAKE_PROCESS_PATH_W) - sizeof(WCHAR));

            // 修改 CommandLine (通常也需要改，不然会被看穿)
            // 这里简单粗暴地把命令行也改成路径，或者你可以传个 fakeCmd 进来
            if (pParams->CommandLine.Buffer && newLen <= pParams->CommandLine.MaximumLength) {
                RtlZeroMemory(pParams->CommandLine.Buffer, pParams->CommandLine.MaximumLength);
                RtlCopyMemory(pParams->CommandLine.Buffer, FAKE_PROCESS_PATH_W, newLen);
                pParams->CommandLine.Length = newLen;

                DbgPrint("Protector: PEB spoofed successfully.\n");
            } else {
                DbgPrint("Protector: Fake path is too long for the original buffer!\n");
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 捕获页面错误 (防止用户态内存无效导致蓝屏)
        DbgPrint("Protector: Exception access PEB!\n");
        status = GetExceptionCode();
    }

    // 解除挂靠
    KeUnstackDetachProcess(&ApcState);

    return status;
}

// 用于修改进程名的工作项上下文结构体
typedef struct _PROCESS_INFO_CONTEXT {
    HANDLE ProcessId;
    PIO_WORKITEM WorkItem;
} PROCESS_INFO_CONTEXT, *PPROCESS_INFO_CONTEXT;

// 隐藏新进程
VOID HideProcessRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    PPROCESS_INFO_CONTEXT pContext = (PPROCESS_INFO_CONTEXT)Context;
    HANDLE processId = pContext->ProcessId;
    PEPROCESS Process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(processId, &Process))) {
        // 修改进程名
        PUCHAR psName = PsGetProcessImageFileName(Process);
        RtlCopyMemory(psName, FAKE_PROCESS_NAME, sizeof(FAKE_PROCESS_NAME));
        // 调试信息
        DbgPrint("Protector: Modified process name to: %s\n", psName);

        // 修改进程路径
        PSE_AUDIT_PROCESS_CREATION_INFO pSeAuditInfo = (PSE_AUDIT_PROCESS_CREATION_INFO)((PUCHAR)Process + SeAuditProcessCreationInfoOffset);
        if (pSeAuditInfo->ImageFileName->Name.Buffer && pSeAuditInfo->ImageFileName->Name.Length >= sizeof(FAKE_PROCESS_NTPATH_W)) {
            PWCH pathBuffer = pSeAuditInfo->ImageFileName->Name.Buffer;
            RtlCopyMemory(pathBuffer, FAKE_PROCESS_NTPATH_W, sizeof(FAKE_PROCESS_NTPATH_W));
            pSeAuditInfo->ImageFileName->Name.Length = sizeof(FAKE_PROCESS_NTPATH_W) - sizeof(WCHAR);

            // 调试信息
            DbgPrint("Protector: Modified process path to: %wZ\n", &pSeAuditInfo->ImageFileName->Name);
        }

        // 断链
        PLIST_ENTRY pActiveLinks = (PLIST_ENTRY)((PUCHAR)Process + ActiveProcessLinksOffset);
        RemoveEntryList(pActiveLinks);
        ULLSetInsert(&ProtectedListEntrySet, (ULONG_PTR)pActiveLinks);

        // 调试信息
        DbgPrint("Protector: Hid process PID: %lu\n", HandleToUlong(processId));

        // 释放工作项和上下文
        IoFreeWorkItem(pContext->WorkItem);
        ExFreePoolWithTag(pContext, 'Work');
        ObDereferenceObject(Process);
    }
}

// 修改新黑名单进程
VOID ModifyBlacklistedProcess(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    PPROCESS_INFO_CONTEXT pContext = (PPROCESS_INFO_CONTEXT)Context;
    HANDLE processId = pContext->ProcessId;
    PEPROCESS Process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(processId, &Process))) {
        // 移除权限
        RemoveProcessPrivileges(Process);
        // 调试信息
        DbgPrint("Protector: Modified blacklisted process PID: %lu\n", HandleToUlong(processId));

        ObDereferenceObject(Process);
    }

    // 释放工作项和上下文
    IoFreeWorkItem(pContext->WorkItem);
    ExFreePoolWithTag(pContext, 'Work');
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
        PCHAR processName = PsGetProcessImageFileName(Process);
        // 判断是要修改的进程
        if (processName && (StringSetContains(&ProtectProcessSet, (PUCHAR)processName) || StringSetContains(&BlackListSet, (PUCHAR)processName))) {
            // 调试信息
            DbgPrint("Protector: Process created: %s (PID: %lu, Parent PID: %lu)\n", processName, ProcessId, CreateInfo->ParentProcessId);

            // 分配工作项上下文
            PROCESS_INFO_CONTEXT* pContext = (PROCESS_INFO_CONTEXT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_INFO_CONTEXT), 'Work');
            if (pContext) {
                pContext->ProcessId = ProcessId;
                pContext->WorkItem = IoAllocateWorkItem(GlobalDriverObject->DeviceObject);
                if (pContext->WorkItem) {
                    // 投递工作项
                    if (StringSetContains(&ProtectProcessSet, (PUCHAR)processName)) {
                        // 加入保护 PID 集合
                        ULLSetInsert(&ProtectedPidSet, (ULONG_PTR)ProcessId);
                        // 保护进程
                        IoQueueWorkItem(pContext->WorkItem, HideProcessRoutine, CriticalWorkQueue, pContext);
                    } else if (StringSetContains(&BlackListSet, (PUCHAR)processName)) {
                        // 黑名单进程
                        IoQueueWorkItem(pContext->WorkItem, ModifyBlacklistedProcess, CriticalWorkQueue, pContext);
                    }
                } else {
                    ExFreePoolWithTag(pContext, 'Work');
                }
            }
        }
    } else {
        // 进程退出，移除保护 PID
        if (ULLSetContains(&ProtectedPidSet, (ULONG_PTR)ProcessId)) {
            ULLSetRemove(&ProtectedPidSet, (ULONG_PTR)ProcessId);
            DbgPrint("Protector: Protected process exited. PID: %lu\n", ProcessId);
        }

        // 断链的进程重新链回
        PLIST_ENTRY pActiveLinks = (PLIST_ENTRY)((PUCHAR)Process + ActiveProcessLinksOffset);
        if (ULLSetContains(&ProtectedListEntrySet, (ULONG_PTR)pActiveLinks)) {
            PLIST_ENTRY activeProcessListEntry = (PLIST_ENTRY)((PUCHAR)PsInitialSystemProcess + ActiveProcessLinksOffset);
            InsertHeadList(activeProcessListEntry, pActiveLinks);
            ULLSetRemove(&ProtectedListEntrySet, (ULONG_PTR)pActiveLinks);

            DbgPrint("Protector: Re-linked exited process PID: %lu\n", ProcessId);
        }
    }
}