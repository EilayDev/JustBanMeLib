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
	const BYTE byte_array[] = { 0x1, 0x2, '?', 0x4, 0x5, 0x6 };
	std::vector<LPVOID> signatureAddr = signatureScan(handle, TargetModule, byte_array, sizeof(byte_array));
	for (int i = 0; i < signatureAddr.size(); i++) {
		std::cout << std::hex << signatureAddr[i] << "\n";
	}
    getchar();
}