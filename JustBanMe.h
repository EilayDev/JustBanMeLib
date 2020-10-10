#pragma once
#ifndef justBanme
#define justBanme
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

#pragma warning(disable:4996)

#ifdef UNICODE
#define GetModuleBaseAddress GetModuleBaseAddressA
#define GetModule GetModuleA
#else
#define GetModuleBaseAddress GetModuleBaseAddressW
#define GetModule GetModuleW
#endif


#ifdef _WIN64
#define _DWORD DWORD64
#else
#define _DWORD DWORD32
#endif

typedef _DWORD ADDRESS;

struct module {
	_DWORD dwSize, dwBase;
};

extern ADDRESS GetModuleBaseAddressA(DWORD processID, LPCSTR moduleName);
extern ADDRESS GetModuleBaseAddressW(DWORD processID, LPCWCHAR moduleName);
extern module GetModuleW(DWORD processID, LPCWCHAR moduleName);
extern module GetModuleA(DWORD processID, LPCSTR moduleName);
extern DWORD GetProcessID(LPCSTR processName);
extern HANDLE GetProcessHandle(DWORD processID, DWORD dwDesiredAccess = PROCESS_ALL_ACCESS);
extern bool PointerChain(HANDLE handle, LPVOID moduleBase, DWORD offset_array[], DWORD* finalValue, ADDRESS* finalAddress);
extern std::vector<LPVOID> signatureScan(HANDLE hProcess, module Module, const BYTE signature[], const size_t numOfItems);

#endif