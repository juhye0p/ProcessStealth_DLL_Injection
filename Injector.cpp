#include "windows.h"
#include "stdio.h"
#include "tlhelp32.h"
#include "tchar.h"

typedef void (*PFN_SetProcName)(LPCTSTR szProcName);
enum { INJECTION_MODE = 0, EJECTION_MODE };

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("[-] OpenProcessToken Error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		printf("[-] LookupPrivilegeValue Error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	else
		tp.Privileges[0].Attributes = 0;

	//Enable or Disable All Privileges
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[-] AdjustTokenPrivileges Error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[!] The token doesn't have the special privilege!\n");
		return FALSE;
	}
	return TRUE;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath) {
	HANDLE hProc, hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	if (!(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		printf("[-] OpenProcess - [%d] Failed..\n", dwPID);
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProc, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

	hThread = CreateRemoteThread(hProc, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);

	WaitForSingleObject(hThread, 1000);

	VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProc);

	printf("[*] Injected [%d]\n", dwPID);
	return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath) {
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProc, hThread;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc;

	if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
		return FALSE;

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
		if (!_tcsicmp(me.szModule, szDllPath) || !_tcsicmp(me.szExePath, szDllPath)) {
			bFound = TRUE;
			break;
		}
	}

	if (!bFound) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	
	hThread = CreateRemoteThread(hProc, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL);
	
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProc);
	CloseHandle(hSnapshot);
}

BOOL InjectAllProcess(int nMode, LPCTSTR szDllPath) {
	DWORD dwPID = 0;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	Process32First(hSnapshot, &pe);

	do {
		dwPID = pe.th32ProcessID;

		//System Process' PID are lower than 1000
		if (dwPID < 1000)
			continue;
		
		if (nMode == INJECTION_MODE)
			InjectDll(dwPID, szDllPath);

		else
			EjectDll(dwPID, szDllPath);
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return TRUE;
}

int _tmain(int argc, TCHAR* argv[]) {
	int nMode = INJECTION_MODE;
	HMODULE hLib = NULL;
	PFN_SetProcName SetProcName = NULL;
	
	if (argc != 4) {
		printf("\nUsage: DllInjector.exe <-hide|-show>"\
			" <Process Name> <Dll Path>\n\n");
		return 1;
	}

	SetPrivilege(SE_DEBUG_NAME, TRUE);


	hLib = LoadLibrary(argv[3]);
	SetProcName = (PFN_SetProcName)GetProcAddress(hLib, "SetProcName");
	SetProcName(argv[2]);

	DWORD dwPID = 0x00;
	printf("PID: ");
	scanf_s("%d", &dwPID);

	//Inject or Eject Dll to All Process
	if (!_tcsicmp(argv[1], L"-show")) {
		EjectDll(dwPID, argv[3]);
		FreeLibrary(hLib);
		return 0;
		//nMode = EJECTION_MODE;
	}

	InjectDll(dwPID, argv[3]);
	//InjectAllProcess(nMode, argv[3]);


	FreeLibrary(hLib);
	return 0;
}