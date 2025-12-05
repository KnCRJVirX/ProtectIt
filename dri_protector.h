#ifndef DRI_PROTECTOR_H
#define DRI_PROTECTOR_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <ntifs.h>

extern PDRIVER_OBJECT GlobalDriverObject;
extern PVOID GlobalRegistrationHandle;

#endif // DRI_PROTECTOR_H