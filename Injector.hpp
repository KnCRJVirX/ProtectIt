#ifndef INJECTOR_CXX
#define INJECTOR_CXX

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <cctype>

#include <Windows.h>
#include <TlHelp32.h>

#include "Utils.h"

class Injector
{
public:
    virtual bool isInit() const = 0;
    virtual bool inject() = 0;
};

class RemoteThreadInjector : public Injector
{
private:
    HANDLE hProcess;
    std::wstring dllPath;
public:
    RemoteThreadInjector() {
        hProcess = GetCurrentProcess();
    }
    RemoteThreadInjector(DWORD processId, LPCWSTR modulePath) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        dllPath = std::wstring(modulePath);
    }
    RemoteThreadInjector(HANDLE _hProcess, LPCWSTR modulePath) {
        hProcess = _hProcess;
        dllPath = std::wstring(modulePath);
    }
    ~RemoteThreadInjector() {
        if (hProcess != GetCurrentProcess()) {
            CloseHandle(hProcess);
        }
    }
    bool isInit() const {
        return hProcess && dllPath.length();
    }
    void setModulePath(LPCWSTR modulePath) {
        dllPath = std::wstring(modulePath);
    }
    bool inject() {
        if (!isInit()) return false;

        // 分配远程空间
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, (dllPath.length() + 2) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
        // 写入dll路径
        if (!WriteProcessMemory(hProcess, remoteMem, dllPath.data(), (dllPath.length() + 1) * sizeof(WCHAR), NULL)) {
            VirtualFreeEx(hProcess, remoteMem, (dllPath.length() + 2) * sizeof(WCHAR), MEM_RELEASE);
            return false;
        }
        // 获取LoadLibraryW地址
        LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        // 创建远程线程并等待
        HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, remoteMem, 0, NULL);
        WaitForSingleObject(hRemoteThread, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeThread(hRemoteThread, &exitCode);
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, remoteMem, (dllPath.length() + 2) * sizeof(WCHAR), MEM_RELEASE);
        printf("Remote LoadLibraryW returned: 0x%X\n", exitCode);
        if (exitCode == 0) {
            return false;
        }

        return true;
    }
};

class APCInjector : public Injector
{
private:
    HANDLE hProcess;
    std::wstring dllPath;
public:
    APCInjector() {
        hProcess = GetCurrentProcess();
    }
    APCInjector(DWORD processId, LPCWSTR modulePath) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        dllPath = std::wstring(modulePath);
    }
    APCInjector(HANDLE _hProcess, LPCWSTR modulePath) {
        hProcess = _hProcess;
        dllPath = std::wstring(modulePath);
    }
    ~APCInjector() {
        if (hProcess != GetCurrentProcess()) {
            CloseHandle(hProcess);
        }
    }
    bool isInit() const {
        return hProcess && dllPath.length();
    }
    bool inject() {
        if (!isInit()) return false;

        // 分配远程空间
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, (dllPath.length() + 2) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
        // 写入dll路径
        if (!WriteProcessMemory(hProcess, remoteMem, dllPath.data(), (dllPath.length() + 1) * sizeof(WCHAR), NULL)) {
            VirtualFreeEx(hProcess, remoteMem, (dllPath.length() + 2) * sizeof(WCHAR), MEM_RELEASE);
            return false;
        }
        // 获取LoadLibraryW地址
        LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        
        // 遍历线程
        THREADENTRY32 te = {0};
        te.dwSize = sizeof(te);
        HANDLE hAllThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        DWORD targetProcessId = GetProcessId(hProcess);
        if (Thread32First(hAllThread, &te)) {
            do {
                if (te.th32OwnerProcessID == targetProcessId) {
                    // 打开线程
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (!hThread) continue;

                    // 注入APC
                    QueueUserAPC((PAPCFUNC)pLoadLibraryW, hThread, (ULONG_PTR)remoteMem);

                    // 关闭句柄
                    CloseHandle(hThread);
                }
            } while (Thread32Next(hAllThread, &te));
        }
        
        // 关闭句柄
        CloseHandle(hAllThread);
        return true;
    }
};

class HijackContextInjector : public Injector
{
private:
    HANDLE hProcess;
    DWORD threadId;
    std::wstring dllPath;
public:
    HijackContextInjector() {
        hProcess = GetCurrentProcess();
        threadId = 0;
    }
    HijackContextInjector(DWORD processId, LPCWSTR modulePath, DWORD _threadId = 0) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        dllPath = std::wstring(modulePath);
        threadId = _threadId;
    }
    HijackContextInjector(HANDLE _hProcess, LPCWSTR modulePath, DWORD _threadId = 0) {
        hProcess = _hProcess;
        dllPath = std::wstring(modulePath);
        threadId = _threadId;
    }
    ~HijackContextInjector() {
        if (hProcess != GetCurrentProcess()) {
            CloseHandle(hProcess);
        }
    }
    bool isInit() const {
        return hProcess && dllPath.length();
    }
    bool injectImpl(DWORD targetThreadId) {
        if (!isInit()) return false;

        // 分配远程空间
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, (dllPath.length() + 2) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
        // 写入dll路径
        if (!WriteProcessMemory(hProcess, remoteMem, dllPath.data(), (dllPath.length() + 1) * sizeof(WCHAR), NULL)) {
            VirtualFreeEx(hProcess, remoteMem, (dllPath.length() + 2) * sizeof(WCHAR), MEM_RELEASE);
            return false;
        }
        // 获取LoadLibraryW地址
        LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        
        // 遍历线程
        THREADENTRY32 te = {0};
        te.dwSize = sizeof(te);
        HANDLE hAllThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (Thread32First(hAllThread, &te)) {
            do {
                if (te.th32ThreadID == targetThreadId) {
                    // 打开线程
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (!hThread) continue;

                    // 暂停线程
                    SuspendThread(hThread);

                    // 读取上下文
                    CONTEXT cxt = {0};
                    cxt.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThread, &cxt);

                    // std::cout << "Rip: " << std::hex << cxt.Rip << std::dec << std::endl;

                    // 判断是否需要对齐
                    bool needAlign = false;
                    if (cxt.Rip % 16 == 0) {
                        // 若已对齐，则压入6个寄存器后要手动-8
                        needAlign = true;
                    }

                    // 构造shellcode
                    std::vector<unsigned char> shellcode;
                    // push rcx, rdx, r8 ~ r11
                    unsigned char pushes[] = {0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53};
                    for (int i = 0; i < sizeof(pushes) / pushes[0]; ++i) {
                        shellcode.push_back(pushes[i]);
                    }
                    // mov rcx, remoteMem
                    shellcode.push_back(0x48);
                    shellcode.push_back(0xB9);
                    for (int i = 0; i < sizeof(void*); ++i) {
                        shellcode.push_back(*((unsigned char*)&remoteMem + i));
                    }
                    // mov rax, pLoadLibraryW
                    shellcode.push_back(0x48);
                    shellcode.push_back(0xB8);
                    for (int i = 0; i < sizeof(void*); ++i) {
                        shellcode.push_back(*((unsigned char*)&pLoadLibraryW + i));
                    }
                    // sub rsp, 8 栈对齐
                    if (needAlign) {
                        shellcode.push_back(0x48);
                        shellcode.push_back(0x83);
                        shellcode.push_back(0xEC);
                        shellcode.push_back(0x08);
                    }
                    // call rax
                    shellcode.push_back(0xFF);
                    shellcode.push_back(0xD0);
                    // add rsp, 8
                    if (needAlign) {
                        shellcode.push_back(0x48);
                        shellcode.push_back(0x83);
                        shellcode.push_back(0xC4);
                        shellcode.push_back(0x08);
                    }
                    // pop r11 ~ r8, rdx, rcx
                    unsigned char pops[] = {0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59};
                    for (int i = 0; i < sizeof(pops) / pops[0]; ++i) {
                        shellcode.push_back(pops[i]);
                    }
                    // mov rax, oldRip
                    shellcode.push_back(0x48);
                    shellcode.push_back(0xB8);
                    for (int i = 0; i < sizeof(void*); ++i) {
                        shellcode.push_back(*((unsigned char*)&cxt.Rip + i));
                    }
                    // jmp rax
                    shellcode.push_back(0xFF);
                    shellcode.push_back(0xE0);

                    // 分配内存
                    LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    // 写入shellcode
                    WriteProcessMemory(hProcess, remoteShellcode, shellcode.data(), shellcode.size(), NULL);

                    // 修改上下文
                    cxt.Rip = (DWORD64)remoteShellcode;
                    SetThreadContext(hThread, &cxt);

                    // 恢复线程
                    ResumeThread(hThread);

                    // 关闭句柄
                    CloseHandle(hThread);
                    break;
                }
            } while (Thread32Next(hAllThread, &te));
        }
        
        // 关闭句柄
        CloseHandle(hAllThread);
        return true;
    }
    bool inject() {
        if (!threadId) return false;
        return injectImpl(this->threadId);
    }
    bool inject(DWORD _threadId) {
        return injectImpl(_threadId);
    }
};

class Hidder
{
private:
    HANDLE hProcess;
    std::wstring moduleName;
    std::wstring wstringUpr(const std::wstring& str) {
        std::wstring res;
        res.resize(str.size());
        std::transform(str.begin(), str.end(), res.begin(), [](wchar_t c){ return std::toupper(c); });
        return res;
    }
public:
    Hidder() {}
    Hidder(DWORD processId, LPCWSTR _moduleName) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        moduleName = wstringUpr(_moduleName);
    }
    Hidder(HANDLE _hProcess, LPCWSTR _moduleName) {
        hProcess = _hProcess;
        moduleName = wstringUpr(_moduleName);
    }
    ~Hidder() {
        if (hProcess != GetCurrentProcess()) {
            CloseHandle(hProcess);
        }
    }
    bool isInit() const {
        return hProcess && moduleName.length();
    }
    PPEB getPEBAddress() const {
        PROCESS_BASIC_INFORMATION remoteProcessInfo = {0};
        ULONG readSize = 0;

        // 读取进程信息
        NtQueryInformationProcess(hProcess, ProcessBasicInformation, &remoteProcessInfo, sizeof(remoteProcessInfo), &readSize);
        if (readSize == 0) {
            return nullptr;
        }

        return remoteProcessInfo.PebBaseAddress;
    }
    bool hide() {
        // 获取PEB地址
        PPEB pPeb = getPEBAddress();
        if (pPeb == nullptr) {
            return false;
        }

        // 读取PEB
        SIZE_T readSize = 0;
        PEB remotePeb = {0};
        ReadProcessMemory(hProcess, pPeb, &remotePeb, sizeof(remotePeb), &readSize);
        if (readSize == 0) {
            return false;
        }

        // 读取LdrData
        PEB_LDR_DATA_FULL remoteLdrData = {0};
        ReadProcessMemory(hProcess, remotePeb.Ldr, &remoteLdrData, sizeof(remoteLdrData), &readSize);
        if (readSize == 0) {
            return false;
        }

        // 遍历
        PLIST_ENTRY head = &remoteLdrData.InLoadOrderModuleList;
        PLIST_ENTRY ptr = head->Flink;
        do {
            // 取到LDR_DATA_TABLE_ENTRY的位置
            LDR_DATA_TABLE_ENTRY_FULL* pLdrDataEntry = CONTAINING_RECORD(ptr, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

            // 读取LDR_DATA_TABLE_ENTRY
            LDR_DATA_TABLE_ENTRY_FULL ldrDataTableEntry = {0};
            ReadProcessMemory(hProcess, pLdrDataEntry, &ldrDataTableEntry, sizeof(ldrDataTableEntry), &readSize);
            if (readSize == 0) {
                return false;
            }
            
            // 读取模块路径并转换为大写
            size_t modulePathLen = ldrDataTableEntry.FullDllName.Length + sizeof(WCHAR);
            std::unique_ptr<WCHAR[]> modulePathBuf = std::make_unique<WCHAR[]>(modulePathLen);
            ReadProcessMemory(hProcess, ldrDataTableEntry.FullDllName.Buffer, modulePathBuf.get(), ldrDataTableEntry.FullDllName.Length, &readSize);
            if (readSize == 0) {
                return false;
            }
            std::wstring modulePath = wstringUpr(modulePathBuf.get());

            // 匹配则切除
            BOOL retval = 0;
            if (modulePath.find(moduleName) != std::wstring::npos) {
                // 切InLoadOrderLinks链
                printf("Cutting InLoadOrderLinks ... ");
                retval = WriteProcessMemory(hProcess, ldrDataTableEntry.InLoadOrderLinks.Blink, &(ldrDataTableEntry.InLoadOrderLinks.Flink), sizeof(PVOID), NULL);
                retval = WriteProcessMemory(hProcess, ldrDataTableEntry.InLoadOrderLinks.Flink + sizeof(PVOID), &(ldrDataTableEntry.InLoadOrderLinks.Blink), sizeof(PVOID), NULL);
                if (retval) printf("Success.\n");
                else printf("Fail.\n");

                // 切InMemoryOrderLinks链
                printf("Cutting InMemoryOrderLinks ... ");
                retval = WriteProcessMemory(hProcess, ldrDataTableEntry.InMemoryOrderLinks.Blink, &(ldrDataTableEntry.InMemoryOrderLinks.Flink), sizeof(PVOID), NULL);
                retval = WriteProcessMemory(hProcess, ldrDataTableEntry.InMemoryOrderLinks.Flink + sizeof(PVOID), &(ldrDataTableEntry.InMemoryOrderLinks.Blink), sizeof(PVOID), NULL);
                if (retval) printf("Success.\n");
                else printf("Fail.\n");

                // 切InInitializationOrderLinks链
                printf("Cutting InInitializationOrderLinks ... ");
                retval = WriteProcessMemory(hProcess, ldrDataTableEntry.InInitializationOrderLinks.Blink, &(ldrDataTableEntry.InInitializationOrderLinks.Flink), sizeof(PVOID), NULL);
                retval = WriteProcessMemory(hProcess, ldrDataTableEntry.InInitializationOrderLinks.Flink + sizeof(PVOID), &(ldrDataTableEntry.InInitializationOrderLinks.Blink), sizeof(PVOID), NULL);
                if (retval) printf("Success.\n");
                else printf("Fail.\n");

                break;
            }

            ptr = ldrDataTableEntry.InLoadOrderLinks.Flink;
        } while (ptr != head);
        return true;
    }
};

#endif