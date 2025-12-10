#include <windows.h>

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM isChildWindow)
{
    DWORD windowPID;
    GetWindowThreadProcessId(hwnd, &windowPID);

    if (windowPID == GetCurrentProcessId())
    {
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
    }
    
    return TRUE;
}

VOID WorkFunc(LPVOID hModule)
{
    Sleep(500);
    while (TRUE) {
        EnumWindows(EnumWindowsProc, FALSE);
        Sleep(2000);
    }
    FreeLibraryAndExitThread((HMODULE)hModule, 0);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkFunc, (LPVOID)hinstDLL, 0, NULL);
    }
    return TRUE;
}