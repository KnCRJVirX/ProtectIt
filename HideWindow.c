#include "HideWindow.h"

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM isChildWindow)
{
    DWORD windowPID;
    GetWindowThreadProcessId(hwnd, &windowPID);

    if (windowPID == GetCurrentProcessId()) {
        // 获取当前的扩展样式
        LONG_PTR style = GetWindowLongPtr(hwnd, GWL_EXSTYLE);

        // 修改样式：
        //    - 添加 WS_EX_TOOLWINDOW (让它像工具栏窗口一样，不显示在任务栏)
        //    - 移除 WS_EX_APPWINDOW (移除强制显示在任务栏的属性)
        style = (style | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW;

        // 应用新样式
        SetWindowLongPtr(hwnd, GWL_EXSTYLE, style);

        // 反截图
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
        
        // 抹掉窗口名
        SetWindowTextW(hwnd, L" ");
    }
    
    return TRUE;
}

VOID WorkFunc(LPVOID hModule)
{
    for (int i = 0; i < 5; i++) {
        EnumWindows(EnumWindowsProc, FALSE);
        Sleep(200);
    }
    while (TRUE) {
        EnumWindows(EnumWindowsProc, FALSE);
        Sleep(2000);
    }
    FreeLibraryAndExitThread((HMODULE)hModule, 0);
}

VOID ModifyPEB() {
    // 等待一会，确保程序已经使用完命令行了
    Sleep(500);

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG length = 0;
    NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &length);
    if (length > 0) {
        PM_PEB pPeb = (PM_PEB)pbi.PebBaseAddress;
        PM_RTL_USER_PROCESS_PARAMETERS pParam = pPeb->ProcessParameters;

        // 窗口名
        UNICODE_STRING fakeWindowName = RTL_CONSTANT_STRING(FAKE_WINDOW_NAME_W);
        if (pParam->WindowTitle.MaximumLength > fakeWindowName.Length) {
            // 够长度，则修改
            RtlCopyMemory(pParam->WindowTitle.Buffer, fakeWindowName.Buffer, fakeWindowName.Length + sizeof(WCHAR));
            pParam->WindowTitle.Length = fakeWindowName.Length;
        } else {
            // 不够长度，直接抹除
            RtlZeroMemory(pParam->WindowTitle.Buffer, pParam->WindowTitle.Length);
            pParam->WindowTitle.Length = 0;
        }

        // 命令行
        UNICODE_STRING fakeCmdLine = RTL_CONSTANT_STRING(FAKE_PROCESS_PATH_W);
        if (pParam->CommandLine.MaximumLength > fakeCmdLine.Length) {
            // 够长度，则修改
            RtlCopyMemory(pParam->CommandLine.Buffer, fakeCmdLine.Buffer, fakeCmdLine.Length + sizeof(WCHAR));
            pParam->CommandLine.Length = fakeCmdLine.Length;
        } else {
            // 不够长度，直接抹除
            RtlZeroMemory(pParam->CommandLine.Buffer, pParam->CommandLine.Length);
            pParam->CommandLine.Length = 0;
        }
    }
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ModifyPEB, (LPVOID)hinstDLL, 0, NULL);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkFunc, (LPVOID)hinstDLL, 0, NULL);
    }
    return TRUE;
}