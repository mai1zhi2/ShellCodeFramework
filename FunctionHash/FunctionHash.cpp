#include <windows.h>
#include <stdio.h>

//获取函数名的hash
DWORD GetProcHash(char* lpProcName) {
	char* p = lpProcName;
	DWORD result = 0;
	do {
		result = (result << 7) - result;
		result += *p;
		//++p;
	} while (*p++);

	return result;
}

int main() {
	char a[] = "MessageBoxA";
	DWORD c = GetProcHash(a);
	printf("%d",c);

	return 0;
}