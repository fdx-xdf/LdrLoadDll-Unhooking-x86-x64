#include <Windows.h>
#include <stdio.h>

#define OBJ_CASE_INSENSITIVE 0x00000040L



typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

using pNewLdrLoadDll = NTSTATUS(NTAPI*)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

typedef int(WINAPI* pMessageBoxW)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType
	);
PVOID CCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

int main()
{

	pNewLdrLoadDll LdrLoadrDll;
	UNICODE_STRING ldrldll;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	wchar_t ldrstring[] = L"User32.dll";

	//Obtaining LdrLoadDll Address from loaded NTDLL
	RtlInitUnicodeString(&ldrldll, ldrstring);
	InitializeObjectAttributes(&objectAttributes, &ldrldll, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	FARPROC  origLdrLoadDll = GetProcAddress(hNtdll, "LdrLoadDll");
	#ifdef _WIN64
	//Setting up the structure of the trampoline for the instructions
	unsigned char jumpPrelude[] = { 0x49, 0xBB };
	unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
	unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3, 0xC3 };
	LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x5);
	*(void**)(jumpAddress) = jmpAddr;
	LPVOID trampoline = VirtualAlloc(NULL, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	// mov qword ptr[rsp + 10h]  原始的LdrLoadDll中汇编，使用我们自己的防止被hook
	// mov r11,address
	// jmp rll
	// ret
	CCopyMemory(trampoline, (PVOID)"\x48\x89\x5c\x24\x10", 5);
	//Setting up the JMP address in the original LdrLoadDll
	CCopyMemory((PBYTE)trampoline + 5, jumpPrelude, 2);
	CCopyMemory((PBYTE)trampoline + 5 + 2, jumpAddress, sizeof(jumpAddress));
	CCopyMemory((PBYTE)trampoline + 5 + 2 + 8, jumpEpilogue, 4);
	DWORD oldProtect = 0;
	VirtualProtect(trampoline, 30, PAGE_EXECUTE_READ, &oldProtect);
	LdrLoadrDll = (pNewLdrLoadDll)trampoline;

	//Loading User32.dll
	HANDLE User32module = NULL;
	LdrLoadrDll(NULL, 0, &ldrldll, &User32module);
	pMessageBoxW MyMessageBoxW = (pMessageBoxW)GetProcAddress((HMODULE)User32module, "MessageBoxW");
	MyMessageBoxW(0, 0, 0, 0);
	#else
	//  x86 架构下的代码
	//  mov    edi, edi
	//  push   ebp
	//  mov    ebp, esp
	//  mov eax,address 
	//  jmp eax
	//  ret
	LPVOID trampoline = VirtualAlloc(NULL, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x5);

	unsigned char jumpPrelude[] = { 0xB8 };
	unsigned char jumpAddress[] = { 0x65, 0x72, 0x45, 0x77 };
	unsigned char jumpEpilogue[] = { 0xFF, 0xE0, 0xC3 };
	*(void**)(jumpAddress) = jmpAddr;
		
	CCopyMemory(trampoline, (PVOID)"\x89\xFF\x55\x89\xE5", 5);
	CCopyMemory((PBYTE)trampoline + 5, jumpPrelude, sizeof jumpPrelude);
	CCopyMemory((PBYTE)trampoline + 5 + sizeof jumpPrelude, jumpAddress, sizeof jumpAddress);
	CCopyMemory((PBYTE)trampoline + 5 + sizeof jumpPrelude + sizeof jumpAddress, jumpEpilogue, sizeof jumpEpilogue);
	DWORD oldProtect = 0;
	VirtualProtect(trampoline, 30, PAGE_EXECUTE_READ, &oldProtect);
	LdrLoadrDll = (pNewLdrLoadDll)trampoline;

	//Loading User32.dll
	HANDLE User32module = NULL;
	LdrLoadrDll(NULL, 0, &ldrldll, &User32module);
	pMessageBoxW MyMessageBoxW = (pMessageBoxW)GetProcAddress((HMODULE)User32module, "MessageBoxW");
	MyMessageBoxW(0, 0, 0, 0);
	#endif


}
