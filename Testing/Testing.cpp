// Testing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../JustBanMe.h"
#include "../JustBanMe.cpp"

int main()
{
	DWORD processID = GetProcessID("VictimProgram");
	HANDLE handle = GetProcessHandle(processID);
	module TargetModule = GetModule(processID, "VictimProgram.exe");
	const BYTE byte_array[] = { 0x21, 0x22, '?', 0x24, 0x25, 0x26 };
	std::vector<LPVOID> signatureAddr = signatureScan(handle, TargetModule, byte_array, sizeof(byte_array));
	for (int i = 0; i < signatureAddr.size(); i++) {
		std::cout << std::hex << signatureAddr[i] << "\n";
	}
    getchar();
}