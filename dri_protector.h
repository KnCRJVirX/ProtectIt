#ifndef DRI_PROTECTOR_H
#define DRI_PROTECTOR_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <ntifs.h>

extern PDRIVER_OBJECT GlobalDriverObject;

VOID CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info);

#endif // DRI_PROTECTOR_H