#include <windows.h>

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM isChildWindow)
{
    DWORD windowPID;
    GetWindowThreadProcessId(hwnd, &windowPID);

    if (windowPID == GetCurrentProcessId())
    {
        // if (!isChildWindow)
        // {
        //     EnumChildWindows(hwnd, EnumWindowsProc, TRUE);
        // }
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
    }
    
    return TRUE;
}

VOID WorkFunc(LPVOID hModule)
{
    EnumWindows(EnumWindowsProc, FALSE);
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