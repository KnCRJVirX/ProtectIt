#ifndef GET_INFO_UTILS
#define GET_INFO_UTILS

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>


// PEB_LDR_DATA的完整定义
typedef struct _PEB_LDR_DATA_FULL   /* Size=0x58 */
{
    /* 0x0000 */ uint32_t Length;
    /* 0x0004 */ unsigned char Initialized;
    unsigned char Padding[3];
    /* 0x0008 */ void* SsHandle;
    /* 0x0010 */ LIST_ENTRY InLoadOrderModuleList;
    /* 0x0020 */ LIST_ENTRY InMemoryOrderModuleList;
    /* 0x0030 */ LIST_ENTRY InInitializationOrderModuleList;
    /* 0x0040 */ void* EntryInProgress;
    /* 0x0048 */ unsigned char ShutdownInProgress;
    unsigned char Padding2[3];
    /* 0x0050 */ void* ShutdownThreadId;
}PEB_LDR_DATA_FULL;

// LDR_DATA_TABLE_ENTRY 的完整定义
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;             // 0x00
    LIST_ENTRY InMemoryOrderLinks;           // 0x10
    LIST_ENTRY InInitializationOrderLinks;   // 0x20
    PVOID DllBase;                           // 0x30
    PVOID EntryPoint;                        // 0x38
    ULONG SizeOfImage;                       // 0x40
    UNICODE_STRING FullDllName;              // 0x48
    UNICODE_STRING BaseDllName;              // 0x58
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// UTF-8, GBK, UTF-16 互相转
#define M_BUF_SIZ 65536
static char gbk_buffer[M_BUF_SIZ];
static char utf8_buffer[M_BUF_SIZ];
static wchar_t utf16_buffer[M_BUF_SIZ];
static inline wchar_t* utf8toutf16(const char* utf8text, wchar_t* utf16text, int utf16text_size)
{
    MultiByteToWideChar(CP_UTF8, 0, utf8text, -1, utf16text, utf16text_size);
    return utf16text;
}
static inline char* utf16toutf8(const wchar_t* utf16text, char* utf8text, int utf8text_size)
{
    WideCharToMultiByte(CP_UTF8, 0, utf16text, -1, utf8text, utf8text_size, NULL, NULL);
    return utf8text;
}
static inline char* utf8togbk(const char* utf8text, char* gbktext, int gbktext_size)
{
    int utf16_text_len = (strlen(utf8text) + 1) * 2;
    wchar_t* utf16text = (wchar_t*)calloc(utf16_text_len, sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, utf8text, -1, utf16text, utf16_text_len);
    WideCharToMultiByte(936, 0, utf16text, -1, gbktext, gbktext_size, NULL, NULL);
    free(utf16text);
    return gbktext;
}
static inline char* gbktoutf8(const char* gbktext, char* utf8text, size_t utf8text_size)
{
    int utf16_text_len = (strlen(gbktext) + 1) * 2;
    wchar_t* utf16text = (wchar_t*)calloc(utf16_text_len, sizeof(wchar_t));
    MultiByteToWideChar(936, 0, gbktext, -1, utf16text, utf16_text_len);
    WideCharToMultiByte(CP_UTF8, 0, utf16text, -1, utf8text, utf8text_size, NULL, NULL);
    free(utf16text);
    return utf8text;
}

static inline LPCWSTR toWideChar(const char* str, wchar_t* buffer, size_t bufferSize)
{
    MultiByteToWideChar(CP_ACP, 0, str, -1, (LPWSTR)buffer, (int)bufferSize);
    return (LPCWSTR)buffer;
}

// 更改CodePage为UTF8
#define UNICODE_INIT() do { SetConsoleCP(CP_UTF8); SetConsoleOutputCP(CP_UTF8); } while(0)
// 枚举所有进程
static inline BOOL EnumProcess(BOOL (*EnumFunc)(LPPROCESSENTRY32W, LPVOID), LPVOID arg);
// 使用进程名获取PID
static inline DWORD GetProcessIdByName(const LPWSTR processName);
// 获取远程模块句柄
static inline HMODULE GetRemoteModuleHandle(DWORD processId, const LPWSTR moduleName);
// 获取远程模块函数地址
static inline DWORD_PTR GetRemoteProcAddress(HMODULE hRemoteModuleHandle, LPCWSTR moduleName, LPCSTR procName);
// 获取远程进程PEB地址
static inline PPEB GetRemoteProcessPebAddress(DWORD processId);
// 枚举进程模块
static inline BOOL EnumModules(DWORD processId, BOOL (*EnumModulesFunc)(LPMODULEENTRY32W, LPVOID), LPVOID arg);

// 枚举所有进程
static inline BOOL EnumProcess(BOOL (*EnumFunc)(LPPROCESSENTRY32W, LPVOID), LPVOID arg)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed\n");
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            EnumFunc(&pe, arg);
        } while (Process32Next(hSnap, &pe));
    } else {
        printf("Process32First failed\n");
    }

    CloseHandle(hSnap);
    return 0;
}

// 使用进程名获取PID
static inline DWORD GetProcessIdByName(const LPWSTR processName)
{
    // 对所有进程快照
    HANDLE hAllProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hAllProcess == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    WCHAR processNameUpr[MAX_PATH] = {0};
    WCHAR tmpProcessName[MAX_PATH] = {0};
    wcscpy(processNameUpr, processName);
    wcsupr(processNameUpr);
    
    // 遍历快照，找到进程名匹配的
    DWORD resultPID = 0;
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    if (!Process32First(hAllProcess, &pe))
    {
        return 0;
    }
    do
    {
        wcscpy(tmpProcessName, pe.szExeFile);
        wcsupr(tmpProcessName);
        if (!wcscmp(tmpProcessName, processNameUpr))
        {
            resultPID = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hAllProcess, &pe));
    
    CloseHandle(hAllProcess);
    return resultPID;
}

// 获取远程模块句柄
static inline HMODULE GetRemoteModuleHandle(DWORD processId, const LPWSTR moduleName)
{
    // 对进程中所有模块快照
    HANDLE hAllModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hAllModule == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    WCHAR moduleNameUpr[MAX_PATH] = {0};
    WCHAR tmpModuleName[MAX_PATH] = {0};
    wcscpy(moduleNameUpr, moduleName);
    wcsupr(moduleNameUpr);
    
    // 遍历快照，找到模块名匹配的
    HMODULE resulthModule = NULL;
    MODULEENTRY32 me = {0};
    me.dwSize = sizeof(me);
    if (!Module32First(hAllModule, &me))
    {
        CloseHandle(hAllModule);
        return NULL;
    }
    do
    {
        wcscpy(tmpModuleName, me.szModule);
        wcsupr(tmpModuleName);
        if (!wcscmp(tmpModuleName, moduleNameUpr))
        {
            printf("From Process:%d Found module: %s\n", processId, utf16toutf8(me.szModule, utf8_buffer, M_BUF_SIZ));
            resulthModule = me.hModule;
            break;
        }
    } while (Module32Next(hAllModule, &me));
    CloseHandle(hAllModule);
    
    return resulthModule;
}

// 获取远程模块函数地址
static inline DWORD_PTR GetRemoteProcAddress(HMODULE hRemoteModuleHandle, LPCWSTR moduleName, LPCSTR procName)
{
    // 加载模块，获取函数地址
    HMODULE hModule = LoadLibraryW(moduleName);
    if (hModule == NULL)
    {
        return (DWORD_PTR)NULL;
    }
    FARPROC procAddr = GetProcAddress(hModule, procName);
    FreeLibrary(hModule);
    if (procAddr == NULL)
    {
        return (DWORD_PTR)NULL;
    }
    
    // 计算偏移量
    DWORD_PTR offset = (DWORD_PTR)procAddr - (DWORD_PTR)hModule;

    // 将偏移量加在基址（模块句柄）上返回
    return (DWORD_PTR)hRemoteModuleHandle + (DWORD_PTR)offset;
}

// 获取远程进程PEB地址
static inline PPEB GetRemoteProcessPebAddress(DWORD processId)
{
    PROCESS_BASIC_INFORMATION remoteProcessInfo = {0};
    ULONG readSize = 0;

    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) goto err;

    // 获取PEB地址
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &remoteProcessInfo, sizeof(remoteProcessInfo), &readSize);
    if (readSize == 0) goto err;

    CloseHandle(hProcess);
    return remoteProcessInfo.PebBaseAddress;

    err:
    CloseHandle(hProcess);
    return NULL;
}

// 枚举进程模块
static inline BOOL EnumModules(DWORD processId, BOOL (*EnumModulesFunc)(LPMODULEENTRY32W, LPVOID), LPVOID arg)
{
    HANDLE hAllModules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hAllModules == INVALID_HANDLE_VALUE) return FALSE;
    MODULEENTRY32W me = {0};
    me.dwSize = sizeof(me);
    Module32FirstW(hAllModules, &me);
    do
    {
        if (!EnumModulesFunc(&me, arg)) break;
    } while (Module32NextW(hAllModules, &me));
    CloseHandle(hAllModules);
    return TRUE; 
}

#endif