#include "dri_notify.h"
#include "dri_protector.h"

NTSTATUS InitNotify(PDRIVER_OBJECT pDriverObject) {
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)pDriverObject->DeviceObject->DeviceExtension;

    InitializeListHead(&pdx->PendingIrpQueue);
    KeInitializeSpinLock(&pdx->QueueLock);

    return status;
}

VOID OnIrpCancel(PDEVICE_OBJECT pDeviceObject, PIRP Irp){
    PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    KIRQL oldIrql;

    // 获取全局锁（取消自旋锁）
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    // 获取我们自己的队列锁
    KeAcquireSpinLock(&pdx->QueueLock, &oldIrql);

    // 从队列中移除
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);

    KeReleaseSpinLock(&pdx->QueueLock, oldIrql);

    // 完成 IRP
    CompleteIrp(Irp, STATUS_CANCELLED, 0);
}

NTSTATUS CreateNotify(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
    PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    KIRQL oldIrql;
    // 获取锁
    KeAcquireSpinLock(&pdx->QueueLock, &oldIrql);

    // 设置取消例程 (为了处理用户按Ctrl+C或进程退出的情况)
    IoSetCancelRoutine(Irp, OnIrpCancel);

    // 检查 IRP 是否已经在获取锁之前被取消了
    if (Irp->Cancel)
    {
        // 如果已经取消，清除取消例程，直接完成
        if (IoSetCancelRoutine(Irp, NULL))
        {
            KeReleaseSpinLock(&pdx->QueueLock, oldIrql);
            // IRP 已取消，完成它
            Irp->IoStatus.Status = STATUS_CANCELLED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_CANCELLED;
        } else {
            // 取消例程已经在运行，锁由取消例程释放
            // 这里什么都不做，让取消例程处理
            KeReleaseSpinLock(&pdx->QueueLock, oldIrql);
            return STATUS_PENDING;
        }
    } else {
        // 将 IRP 标记为挂起
        IoMarkIrpPending(Irp);

        // 放入队列
        InsertTailList(&pdx->PendingIrpQueue, &Irp->Tail.Overlay.ListEntry);

        KeReleaseSpinLock(&pdx->QueueLock, oldIrql);

        // 返回 STATUS_PENDING，告诉系统：“我还没做完，让R3等着”
        return STATUS_PENDING;
    }
}

VOID Notify(PDRIVER_OBJECT pDriverObject, PVOID Data, ULONG DataLength) {
    PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)pDriverObject->DeviceObject->DeviceExtension;
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    // 获取队列锁
    KeAcquireSpinLock(&pdx->QueueLock, &oldIrql);

    // 遍历挂起的 IRP 队列
    while (!IsListEmpty(&pdx->PendingIrpQueue)) {
        entry = pdx->PendingIrpQueue.Flink;
        PIRP Irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

        // 尝试清除取消例程
        if (IoSetCancelRoutine(Irp, NULL) == NULL)
        {
            // 如果返回 NULL，说明取消例程已经在运行了，我们不能动这个 IRP
            // 它是属于取消例程的，我们继续找下一个
            continue;
        }

        // 移除出队列
        RemoveEntryList(entry);

        // 释放锁
        KeReleaseSpinLock(&pdx->QueueLock, oldIrql);

        // 获取用户给的缓冲区总长度
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        ULONG userBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
        
        // 计算实际能拷贝多少
        ULONG toCopy = (userBufferLength < DataLength) ? userBufferLength : DataLength;

        // 拷贝数据
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, Data, toCopy);

        // 告诉 R3 我们写入了多少字节
        Irp->IoStatus.Information = toCopy;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        // 唤醒R3进程
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        // 重新获取锁，继续处理下一个
        KeAcquireSpinLock(&pdx->QueueLock, &oldIrql);
    }

    // 释放锁
    KeReleaseSpinLock(&pdx->QueueLock, oldIrql);
}

VOID NotifyCreateProcess(PDRIVER_OBJECT pDriverObject, PEPROCESS Process) {
    HANDLE pid = PsGetProcessId(Process);
    INT32 dwPid = (INT32)(ULONG_PTR)pid;
    Notify(pDriverObject, &dwPid, sizeof(INT32));

    // 调试信息
    DbgPrint("Protector: Notified process creation, PID: %d\n", dwPid);
}