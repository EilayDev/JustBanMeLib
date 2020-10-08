#include "JustBanMe.h"

DWORD GetProcessID(LPCSTR processName) {
	HWND hwnd = FindWindowA(NULL, processName);
	if (!hwnd) {
		return false;
	}
	DWORD procID;
	if (!GetWindowThreadProcessId(hwnd, &procID)) {
		return false;
	}
	else {
		return procID;
	}
}
LPVOID GetModuleBaseAddressW(DWORD processID, LPCWCHAR moduleName) {
	HANDLE snapshot;
	MODULEENTRY32W pe32;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	pe32.dwSize = sizeof(MODULEENTRY32W);

	if (Module32FirstW(snapshot, &pe32)) {
		if (!wcscmp(moduleName, pe32.szModule)) {
			CloseHandle(snapshot);
			return (LPVOID)pe32.modBaseAddr;
		}
	}
	else {
		return 0;
	}

	while (Module32NextW(snapshot, &pe32)) {
		if (!wcscmp(moduleName, pe32.szModule)) {
			CloseHandle(snapshot);
			return (LPVOID)pe32.modBaseAddr;
		}
	}
	CloseHandle(snapshot);
	return 0;
}

LPVOID GetModuleBaseAddressA(DWORD processID, LPCSTR moduleName) {
	HANDLE snapshot;
	MODULEENTRY32W pe32;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}
	pe32.dwSize = sizeof(MODULEENTRY32);
	LPSTR convertedStr = new CHAR[MAX_MODULE_NAME32];
	
	if (Module32FirstW(snapshot, &pe32)) {
		
		wcstombs(convertedStr, pe32.szModule, wcslen(pe32.szModule) + 1);
		
		if (!strcmp(moduleName, convertedStr)) {
			CloseHandle(snapshot);
			delete [] convertedStr;
			return (LPVOID)pe32.modBaseAddr;
		}
	}
	else {
		CloseHandle(snapshot);
		return NULL;
	}

	while (Module32NextW(snapshot, &pe32)) {
		wcstombs(convertedStr, pe32.szModule, wcslen(pe32.szModule)+1);
		if (!strcmp(moduleName, convertedStr)) {
			delete [] convertedStr;
			CloseHandle(snapshot);
			return (LPVOID)pe32.modBaseAddr;
		}
	}
	CloseHandle(snapshot);
	delete[] convertedStr;
	return NULL;
}

HANDLE GetProcessHandle(DWORD processID, DWORD dwDesiredAccess){
	HANDLE handle = OpenProcess(dwDesiredAccess, false, processID);
	return (!OpenProcess) ? 0 : handle;
}
bool PointerChain(HANDLE handle, LPVOID moduleBase, DWORD offset_array[], DWORD* finalValue, LPVOID* finalAddress) {
	size_t sizeOfArray = sizeof(offset_array) * 2;
	LPVOID address = nullptr;
	
	if (!ReadProcessMemory(handle, (LPVOID)((_DWORD)moduleBase + (DWORD)offset_array[0]), &address, sizeof(address), 0)) { return false; }

	for (int i = 1; i < (sizeOfArray); i++) {
		if (i == (sizeOfArray - 1)) {
			if (!ReadProcessMemory(handle, (LPVOID)((_DWORD)address + (DWORD)offset_array[i]), &finalValue, sizeof(address), 0)) { return false; }
			*(LPVOID*)finalAddress = (LPVOID)((_DWORD)address + offset_array[i]);
			return true;
		}
		if (!ReadProcessMemory(handle, (LPVOID)((_DWORD)address + (DWORD)offset_array[i]), &address, sizeof(address), 0)) { return false; }
	}
}

std::vector<LPVOID> signatureScan(HANDLE hProcess, LPVOID baseAddress, size_t moduleSize, const BYTE signature[], const size_t numOfItems) {
	PBYTE moduleData = new BYTE[moduleSize];
	std::vector<LPVOID> arrayOfHits;
	if (!ReadProcessMemory(hProcess, baseAddress, moduleData, moduleSize, 0)) {
		return (std::vector<LPVOID>)0;
	}

	for (DWORD i = 0; i < moduleSize; i++) {
		if (moduleData[i] == signature[0]) { // if certain byte equals to first byte in signature
			for (DWORD j = 1; j < numOfItems; j++) {
				if (signature[j] == '?') {
					if (j == numOfItems - 1) { goto ret; }
					continue;
				}
				if (signature[j] != moduleData[i + j]) {
					break;
				}
				if (j == numOfItems - 1) {
				ret:
					arrayOfHits.push_back((LPVOID)((_DWORD)baseAddress + i));
					break;
				}
			}
		}

	}
	return arrayOfHits;
}

module GetModuleW(DWORD processID, LPCWCHAR moduleName){
	HANDLE snapshot;
	MODULEENTRY32W pe32;
	module _module;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return _module = {NULL};
	}
	pe32.dwSize = sizeof(MODULEENTRY32W);

	if (Module32FirstW(snapshot, &pe32)) {
		if (!wcscmp(moduleName, pe32.szModule)) {
			CloseHandle(snapshot);
			_module.dwBase = (_DWORD)pe32.modBaseAddr;
			_module.dwSize = pe32.modBaseSize;
			return _module;
		}
	}
	else {
		return _module = { NULL };
	}

	while (Module32NextW(snapshot, &pe32)) {
		if (!wcscmp(moduleName, pe32.szModule)) {
			CloseHandle(snapshot);
			_module.dwBase = (_DWORD)pe32.modBaseAddr;
			_module.dwSize = pe32.modBaseSize;
			return _module;
		}
	}
	CloseHandle(snapshot);
	return _module = { NULL };
}

module GetModuleA(DWORD processID, LPCSTR moduleName) {
	HANDLE snapshot;
	MODULEENTRY32W pe32;
	module _module;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return _module = { NULL };
	}
	pe32.dwSize = sizeof(MODULEENTRY32);
	LPSTR convertedStr = new CHAR[MAX_MODULE_NAME32];

	if (Module32FirstW(snapshot, &pe32)) {
		wcstombs(convertedStr, pe32.szModule, wcslen(pe32.szModule) + 1);

		if (!strcmp(moduleName, convertedStr)) {
			CloseHandle(snapshot);
			delete[] convertedStr;
			_module.dwBase = (_DWORD)pe32.modBaseAddr;
			_module.dwSize = pe32.modBaseSize;
			return _module;
		}
	}
	else {
		CloseHandle(snapshot);
		return _module = { NULL };
	}

	while (Module32NextW(snapshot, &pe32)) {
		wcstombs(convertedStr, pe32.szModule, wcslen(pe32.szModule) + 1);
		if (!strcmp(moduleName, convertedStr)) {
			delete[] convertedStr;
			CloseHandle(snapshot);
			_module.dwBase = (_DWORD)pe32.modBaseAddr;
			_module.dwSize = pe32.modBaseSize;
			return _module;
		}
	}
	CloseHandle(snapshot);
	delete[] convertedStr;
	return _module = { NULL };
}