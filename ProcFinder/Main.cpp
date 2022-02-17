/* if you use certain data types, such as arrays, you need to merge .rdata section to .text section
* This grows the final shellcode size by a lot, so unless necessary, you should avoid this
* For example this configuration has size of 452 bytes
* And by using Ordinals to find the GetNativeSystemInfo address 250 bytes
*/

//Merging .rdata to .text is another option to store arrays
//#pragma comment(linker, "/merge:.rdata=.text")
#include "GetProcAddress.h"
#include <Windows.h>

// Define our string and allocate it to .text section. This results into smaller shellcode than using the merge trick mentioned earlier
// This allocates the string before the executable code, so you must use the offset provided by the build output
//#pragma section(".text")
//__declspec(allocate(".text"))char GetNativeSystemInfoArr[] = { 'G','e','t','N','a','t','i','v','e','S','y','s','t','e','m','I','n','f','o', 0 };

SYSTEM_INFO _code()
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
    char GetNativeSystemInfoArr1[] = { 'G','e','t','N','a','t','i','v','e','S','y','s','t','e','m' };
    char GetNativeSystemInfoArr2[] = { 'I', 'n', 'f', 'o', 0};
    LPCSTR GetNativeSystemInfoArr = strcat(GetNativeSystemInfoArr1, GetNativeSystemInfoArr2);

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

    return sysinfo;
}