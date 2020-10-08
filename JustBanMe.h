#pragma once
#ifndef justBanme
#define justBanme
#include <Windows.h>
#include <TlHelp32.h>

#pragma warning(disable:4996)

#ifdef UNICODE
#define GetModuleBaseAddress GetModuleBaseAddressA
#else
#define GetModuleBaseAddress GetModuleBaseAddressW
#endif

extern LPVOID GetModuleBaseAddressA(DWORD processID, LPCSTR moduleName);
extern LPVOID GetModuleBaseAddressW(DWORD processID, LPCWCHAR moduleName);
extern DWORD GetProcessID(LPCSTR processName);
extern HANDLE GetProcessHandle(DWORD processID, DWORD dwDesiredAccess = PROCESS_ALL_ACCESS);
extern bool PointerChain(HANDLE handle, LPVOID moduleBase, DWORD offset_array[], DWORD* finalValue, LPVOID* finalAddress);

#endif