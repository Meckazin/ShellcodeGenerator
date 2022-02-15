#include <Windows.h>
#include <iostream>
#include "GetProcAddress.h"

char GetNativeSystemInfoArr[] = { 'G','e','t','N','a','t','i','v','e','S','y','s','t','e','m','I','n','f','o', 0 };

int main()
{
    //Function definitions
    typedef FARPROC(WINAPI* GetProcAddressProc)(HMODULE, LPCSTR);
    typedef void(WINAPI* GetNativeSystemInfoProc)(LPSYSTEM_INFO);

    HMODULE hKernel32 = GetKernel32BaseAddress();
    GetProcAddressProc pGetProcAddress = (GetProcAddressProc)GetProcAddressPEB();

    //Get System Info
    GetNativeSystemInfoProc pGetNativeSystemInfo = (GetNativeSystemInfoProc)pGetProcAddress(hKernel32, (LPCSTR)GetNativeSystemInfoArr);
    _SYSTEM_INFO sysinfo;
    pGetNativeSystemInfo(&sysinfo);
    printf("Pagesize: %i\n", sysinfo.dwPageSize);

    return EXIT_SUCCESS;
}
