#pragma once
#include <windows.h>

typedef FARPROC(WINAPI* FN_GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);

typedef HMODULE(WINAPI* FN_LoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	);

typedef int(WINAPI* FN_MessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);

typedef struct tagApiInterface {
	FN_GetProcAddress pfnGetProcAddress;
	FN_LoadLibraryA pfnLoadLibrary;
	FN_MessageBoxA pfnMessageBoxA;
}APIINTERFACE,*PAPIINTERFACE;

DWORD MyGetProcAddress(HMODULE hModule, DWORD lpProcName);
HMODULE GetKernel32Base();
BOOL MyStrcmp(DWORD str1, char* str2);
DWORD GetProcHash(char* lpProcName);