#define _CRT_SECURE_NO_WARNINGS
#include <iostream>

#include <windows.h>
#include <winioctl.h>
#include <Shlwapi.h>
#include "protectordef.h"
#include "Injector.hpp"

#define HIDE_WINDOW_MODULE_NAME L"HideWindow.dll"

enum WorkMode {
    HideWindow,
    Protect,
    Unprotect,
    AddWhite,
    AddBlack
};

HANDLE hDriver = INVALID_HANDLE_VALUE;

BOOL IoCtlDriver(DWORD ioctlCode, const char* processName) {
    ProtectProcessInfo info = { 0 };
    strcpy(info.processName, processName);
    info.processName[sizeof(info.processName) - 1] = 0;

    DWORD bytes = 0;
    printf("Send IOCtl, Code: 0x%X, processname: %s\n", IOCTL_PROT_PROCESS, info.processName);
    BOOL ok = DeviceIoControl(hDriver,
                              ioctlCode,
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

BOOL IoCtlDriverWithReturn(DWORD ioctlCode, PVOID buffer, DWORD bufferSize) {
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(hDriver,
                              ioctlCode,
                              NULL, 0,
                              buffer, bufferSize,
                              &bytes,
                              NULL);

    if (!ok) {
        printf("DeviceIoControl 失败, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }

    printf("OK!\n");
    return TRUE;
}

DWORD WaitForCreateProcess() {
    DWORD processId = 0;
    IoCtlDriverWithReturn(IOCTL_NOTIFY_CREATE_PS, &processId, sizeof(processId));
    printf("Create Process pid: %d\n", processId);
    return processId;
}

BOOL ProtectProcess(const char* processName) {
    return IoCtlDriver(IOCTL_PROT_PROCESS, processName);
}

BOOL AddWhiteProcess(const char* processName) {
    return IoCtlDriver(IOCTL_ADD_WHITE, processName);
}

BOOL UnprotectProcess(const char* processName) {
    return IoCtlDriver(IOCTL_UNPROT_PROCESS, processName);
}

BOOL AddBlackProcess(const char* processName) {
    return IoCtlDriver(IOCTL_ADD_BLACK, processName);
}

BOOL HideWindowProcess(const char* processName) {
    char buffer[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    char* pName = PathFindFileNameA(buffer);
    AddWhiteProcess(pName);

    wchar_t fullPath[MAX_PATH] = { 0 };
    GetFullPathNameW(HIDE_WINDOW_MODULE_NAME, MAX_PATH, fullPath, NULL);
    std::wcout << "HideWindow module path: " << fullPath << L'\n';

    while (true) {
        DWORD pid = WaitForCreateProcess();
        if (pid != 0) {
            printf("New process created, PID: %lu\n", pid);

            // 等一会
            Sleep(100);

            // 隐藏窗口
            APCInjector injector(pid, fullPath);
            if (injector.isInit()) {
                if (injector.inject()) {
                    printf("Injected HideWindow DLL into process %lu successfully.\n", pid);
                } else {
                    printf("Failed to inject HideWindow DLL into process %lu.\n", pid);
                }
            } else {
                printf("Injector not initialized properly for process %lu.\n", pid);
            }
        }
    }

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
        } else if (!strcmp(argv[i], "-hw")) {
            mode = HideWindow;
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
    case HideWindow:
        HideWindowProcess(processName);
        break;
    default:
        break;
    }

    return 0;
}