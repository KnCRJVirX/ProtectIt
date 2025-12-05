#define _CRT_SECURE_NO_WARNINGS
#include <iostream>

#include <windows.h>
#include <winioctl.h>
#include "protectordef.h"

enum WorkMode {
    Protect,
    Unprotect,
    AddWhite,
    AddBlack
};

HANDLE hDriver = INVALID_HANDLE_VALUE;

BOOL ProtectProcess(const char* processName) {
    ProtectProcessInfo info = { 0 };
    strcpy(info.processName, processName);
    info.processName[sizeof(info.processName) - 1] = 0;

    DWORD bytes = 0;
    printf("Send IOCtl, Code: 0x%X, processname: %s\n", IOCTL_PROT_PROCESS, info.processName);
    BOOL ok = DeviceIoControl(hDriver,
                              IOCTL_PROT_PROCESS,
                              &info, sizeof(info),
                              NULL, 0,
                              &bytes,
                              NULL);

    if (!ok) {
        printf("DeviceIoControl 失败, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }

    printf("OK!\n");
    return TRUE;
}

BOOL AddWhiteProcess(const char* processName) {
    ProtectProcessInfo info = { 0 };
    strcpy(info.processName, processName);
    info.processName[sizeof(info.processName) - 1] = 0;

    DWORD bytes = 0;
    printf("Send IOCtl, Code: 0x%X, processname: %s\n", IOCTL_ADD_WHITE, info.processName);
    BOOL ok = DeviceIoControl(hDriver,
                              IOCTL_ADD_WHITE,
                              &info, sizeof(info),
                              NULL, 0,
                              &bytes,
                              NULL);

    if (!ok) {
        printf("DeviceIoControl 失败, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }

    printf("OK!\n");
    return TRUE;
}

BOOL UnprotectProcess(const char* processName) {
    ProtectProcessInfo info = { 0 };
    strcpy(info.processName, processName);
    info.processName[sizeof(info.processName) - 1] = 0;

    DWORD bytes = 0;
    printf("Send IOCtl, Code: 0x%X, processname: %s\n", IOCTL_UNPROT_PROCESS, info.processName);
    BOOL ok = DeviceIoControl(hDriver,
                              IOCTL_UNPROT_PROCESS,
                              &info, sizeof(info),
                              NULL, 0,
                              &bytes,
                              NULL);

    if (!ok) {
        printf("DeviceIoControl 失败, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }

    printf("OK!\n");
    return TRUE;
}

BOOL AddBlackProcess(const char* processName) {
    ProtectProcessInfo info = { 0 };
    strcpy(info.processName, processName);
    info.processName[sizeof(info.processName) - 1] = 0;

    DWORD bytes = 0;
    printf("Send IOCtl, Code: 0x%X, processname: %s\n", IOCTL_ADD_BLACK, info.processName);
    BOOL ok = DeviceIoControl(hDriver,
                              IOCTL_ADD_BLACK,
                              &info, sizeof(info),
                              NULL, 0,
                              &bytes,
                              NULL);

    if (!ok) {
        printf("DeviceIoControl 失败, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }

    printf("OK!\n");
    return TRUE;
}

int main(int argc, const char* argv[]) {
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);

    if (argc < 2) {
        printf("Usage: %s <process_name>\n", argv[0]);
        return 1;
    }

    WorkMode mode = Protect;
    const char* processName = nullptr;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-p")) {
            mode = Protect;
        } else if (!strcmp(argv[i], "-u")) {
            mode = Unprotect;
        } else if (!strcmp(argv[i], "-aw")) {
            mode = AddWhite;
        } else if (!strcmp(argv[i], "-ab")) {
            mode = AddBlack;
        } else if (!strcmp(argv[i], "-im") && i + 1 < argc) {
            processName = argv[i + 1];
            i++;
        }
    }
    
    hDriver = CreateFileW(CREATE_FILE_NAME,
                           GENERIC_READ | GENERIC_WRITE,
                           0,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("打开设备失败, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }

    switch (mode)
    {
    case Protect:
        ProtectProcess(processName);
        break;
    case AddWhite:
        AddWhiteProcess(processName);
        break;
    case Unprotect:
        UnprotectProcess(processName);
        break;
    case AddBlack:
        AddBlackProcess(processName);
        break;
    default:
        break;
    }

    return 0;
}