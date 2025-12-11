#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

HANDLE getFileHandle(LPCWSTR dumpFileName) {
	HANDLE hFile = CreateFileW(dumpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"[-] CreateFileW failed. Error: %lu\n", GetLastError());
		return NULL;
	}

	return hFile;
}

HANDLE getProcessHandle(DWORD PID) {
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
		FALSE,
		PID
	);
	if (hProcess == NULL) {
		wprintf(L"[-] OpenProcess failed. Error: %lu\n", GetLastError());
		return NULL;
	}

	return hProcess;
}

BOOL dumpFile(HANDLE hProcess, HANDLE hFile, DWORD PID) {
	BOOL success = MiniDumpWriteDump(
		hProcess,
		PID,
		hFile,
		MiniDumpWithFullMemory,
		NULL, NULL, NULL
	);

	if (!success) {
		wprintf(L"[-] failed to dump file. Error: %lu\n", GetLastError());
		return FALSE;
	}

	wprintf(L"[+] dump created\n");
	return TRUE;
}

int main() {
	HANDLE hProcess = NULL;
	HANDLE hFile = NULL;
	DWORD PID = 0;

	wprintf(L"Input PID: ");
	scanf_s("%d", &PID);

	hProcess = getProcessHandle(PID);
	if (hProcess == NULL) {
		return EXIT_FAILURE;
	}

	hFile = getFileHandle(L"dump.dmp");
	if (hFile == NULL) {
		goto CLEANUP;
	}

	dumpFile(hProcess, hFile, PID);
	
CLEANUP:
	if (hProcess) {
		CloseHandle(hProcess);
	}

	if (hFile) {
		CloseHandle(hFile);
	}

	return EXIT_SUCCESS;
}