#ifndef DRI_NOTIFY_H
#define DRI_NOTIFY_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <ntifs.h>

// 自定义的设备扩展结构
typedef struct _DEVICE_EXTENSION {
    LIST_ENTRY      PendingIrpQueue;  // 用来存挂起的IRP
    KSPIN_LOCK      QueueLock;        // 保护队列的自旋锁
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS InitNotify(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateNotify(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
VOID Notify(PDRIVER_OBJECT pDriverObject, PVOID Data, ULONG DataLength);
VOID NotifyCreateProcess(PDRIVER_OBJECT pDriverObject, PEPROCESS Process);

#endif // DRI_NOTIFY_H