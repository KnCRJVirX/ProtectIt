#include "protectordef.h"
#include "dri_protector.h"
#include "dri_callbacks.h"
#include "dri_notify.h"

PDRIVER_OBJECT GlobalDriverObject;

VOID CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    CompleteIrp(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    // 注销回调，恢复原状态
    CallbacksResume();

    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrint("Protector: Driver unloaded.\n");
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ProtectProcessInfo* info = (ProtectProcessInfo*)Irp->AssociatedIrp.SystemBuffer;

    switch (code) {
    case IOCTL_PROT_PROCESS: {
        StringSetInsert(&ProtectProcessSet, info->processName);
        status = STATUS_SUCCESS;

        // 调试信息
        DbgPrint("Protect process: %ws\n", info->processName);
        break;
    }
    case IOCTL_UNPROT_PROCESS: {
        // 从保护集合中移除该进程名
        StringSetRemove(&ProtectProcessSet, info->processName);
        status = STATUS_SUCCESS;

        DbgPrint("Unprotect process: %ws\n", info->processName);
        break;
    }
    case IOCTL_ADD_WHITE: {
        StringSetInsert(&WhiteListSet, info->processName);
        status = STATUS_SUCCESS;

        // 调试信息
        DbgPrint("Add whitelist process: %ws\n", info->processName);
        break;
    }
    case IOCTL_ADD_BLACK: {
        StringSetInsert(&BlackListSet, info->processName);
        status = STATUS_SUCCESS;

        // 调试信息
        DbgPrint("Add blacklist process: %ws\n", info->processName);
        break;
    }
    case IOCTL_NOTIFY_CREATE_PS: {
        status = CreateNotify(DeviceObject, Irp);

        // 调试信息
#ifdef _DEBUG
        DbgPrint("Set notify create process IRP.");
#endif
        return status;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    CompleteIrp(Irp, status, 0);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT devObj = NULL;

    UNICODE_STRING devName  = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symLink  = RTL_CONSTANT_STRING(SYMLINK_NAME);

    // 创建设备
    status = IoCreateDevice(
            DriverObject,
            sizeof(DEVICE_EXTENSION),
            &devName,
            FILE_DEVICE_UNKNOWN,
            0,
            FALSE,
            &devObj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Protector: IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    // 初始化Notify
    status = InitNotify(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Protector: InitNotify failed: 0x%X\n", status);
        IoDeleteDevice(devObj);
        return status;
    }

    // 保存全局 DriverObject 指针
    GlobalDriverObject = DriverObject;

    // 使用缓冲 I/O，配合 METHOD_BUFFERED
    devObj->Flags |= DO_BUFFERED_IO;

    // 创建符号链接，供用户态 CreateFile("\\\\.\\KillProc")
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Protector: IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(devObj);
        return status;
    }

    // 初始化回调相关数据
    status = CallbacksInit();
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(devObj);
        return status;
    }

    // 设置分发例程
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint(
        "Protector: Driver loaded. Build for %ws\n",
#ifdef _WIN64
        L"x64"
#else
        L"x86"
#endif
    );

    // 清除初始化标志
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}