#include <windows.h>
#include <stdio.h>
#include <iostream>
#include "Shellcode.h"

using namespace std;

/* 
* Find the entrypoint function offset from <projectname>.map file
* For this example 
* 0001:00000090       _code                      00000001800010d0 f   Main.obj
* You need to use the offset if .rdata was merged into .text section or arrays were stored into .text section
* Or the code for GetProcAddress.h is not merged into Main.cpp
*/
#define FUNCTION_OFFSET 0x00000000

//Definition for our shellcode entry function
typedef _SYSTEM_INFO(*_code)();

int main()
{
	// Set our shellcode to executable
	DWORD old_flag;
	VirtualProtect(rawData, sizeof rawData, PAGE_EXECUTE, &old_flag);

	// Create function from our offset
	//_code fn_code = (_code)(void*)&rawData[FUNCTION_OFFSET];
	// Classic execution from no offset
	_code fn_code = (_code)(void*)rawData;

	//Run it
	_SYSTEM_INFO info = fn_code();
	printf("Pagesize: %i\n", info.dwPageSize);

	return EXIT_SUCCESS;
}