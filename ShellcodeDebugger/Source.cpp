#include <Windows.h>
#include <iostream>
#include "GetProcAddress.h"

int main()
{
    //Function definitions
    typedef FARPROC(WINAPI* GetProcAddressProc)(HMODULE, LPCSTR);
    typedef void(WINAPI* GetNativeSystemInfoProc)(LPSYSTEM_INFO);

    // Find Kernel32 address
    HMODULE hKernel32 = GetKernel32BaseAddress();

    // Find GetProcAddress location and cast it into function stub
    HANDLE hGetProcAddress = GetProcAddressPEB();
    GetProcAddressProc pGetProcAddress = (GetProcAddressProc)hGetProcAddress;

    //GetNativeSystemInfo ProcAddress
    //Use char arrays as we can't use PE's .data section. Arrays longer than 15 elements are stored in the .rdata, this requires you to merge .rdata to .text
    //One trick is to split too long arrays and then concatenate them
    char GetNativeSystemInfoArr[] = { 'G','e','t','N','a','t','i','v','e','S','y','s','t','e','m','I', 'n', 'f', 'o', 0 };

    //You can also just use Ordinals
    //HANDLE hGetNativeSystemInfo = pGetProcAddress(hKernel32, (LPCSTR)652);

    //Get address of systeminfo
    HANDLE hGetNativeSystemInfo = pGetProcAddress(hKernel32, GetNativeSystemInfoArr);
    //Create the function from the pointer
    GetNativeSystemInfoProc pGetNativeSystemInfo = (GetNativeSystemInfoProc)hGetNativeSystemInfo;

    //Initialize output data
    SYSTEM_INFO sysinfo;
    // Call GetNativeSystemInfo
    pGetNativeSystemInfo(&sysinfo);
    printf("Pagesize: %i\n", sysinfo.dwPageSize);

    return EXIT_SUCCESS;
}
