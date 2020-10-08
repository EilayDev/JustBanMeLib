// Testing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../JustBanMe.h"
#include "../JustBanMe.cpp"

int main()
{
    DWORD procID = GetProcessID("Calculator");
    HANDLE pHandle = GetProcessHandle(procID);
    std::cout << pHandle << "\n";
    if (!pHandle) {
        std::cout << "INVALID HANDLE\n";
    }
    
    getchar();
}