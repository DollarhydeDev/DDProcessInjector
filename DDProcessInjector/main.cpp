#include "windows.h"
#include "iostream"
#include "tlhelp32.h"
#include "handleapi.h"

int FindProcessId(const wchar_t* processName)
{
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshotHandle == INVALID_HANDLE_VALUE)
	{
		std::wcerr << L"Failed to take process snapshot" << L"\n";
		return 0;
	}

	bool processFound = Process32FirstW(snapshotHandle, &entry);
	int processId = 0;

	while (processFound)
	{
		if (_wcsicmp(entry.szExeFile, processName) == 0) { processId = entry.th32ProcessID; break; }
		processFound = Process32NextW(snapshotHandle, &entry);
	}

	CloseHandle(snapshotHandle);
	return processId;
}

int wmain(int argc, wchar_t** argv)
{
	if (argc != 2)
	{
		std::wcerr << L"Usage: Injector.exe <process_name.exe>\n";
		std::wcerr << L"Example: Injector.exe SomeApplication.exe";
		return -1;
	}

	const wchar_t* targetProcessName = argv[1];
	wchar_t fullDllPath[MAX_PATH]{};

	DWORD pathLen = GetFullPathNameW(L"payloads\\payload.dll", MAX_PATH, fullDllPath, nullptr);
	if (pathLen == 0 || pathLen >= MAX_PATH)
	{
		std::wcerr << L"GetFullPathNameW failed. Error: " << GetLastError() << L"\n";
		return -1;
	}

	if (GetFileAttributesW(fullDllPath) == INVALID_FILE_ATTRIBUTES)
	{
		std::wcerr << L"DLL does not exist: '" << fullDllPath << L"'. Injector assumes that payloads/payload.dll exists in its directory." L"\n";
		return -1;
	}

	const wchar_t* targetDll = fullDllPath;
	int targetDllByteCount = (wcslen(targetDll) + 1) * sizeof(wchar_t);

	// === Find processes and modules ===

	int processId = FindProcessId(targetProcessName);
	if (processId == 0)
	{
		std::wcerr << L"Failed to locate process" << L"\n";
		return -1;
	}

	std::wcout << L"Located process with id: " << processId << L"\n";

	HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
	if (kernel32Module == nullptr)
	{
		std::wcerr << L"Failed to locate kernel32.dll" << L"\n";
		return -1;
	}

	FARPROC loadLibraryAddress = GetProcAddress(kernel32Module, "LoadLibraryW");
	if (loadLibraryAddress == nullptr)
	{
		std::wcerr << L"Failed to locate LoadLibraryW inside kernel32.dll" << L"\n";
		return -1;
	}

	// ==============================

	// === Allocate and write memory ===

	HANDLE targetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, processId);
	if (targetProcessHandle == nullptr)
	{
		std::wcerr << L"Failed to open process. Error: " << GetLastError() << L"\n";
		return -1;
	}

	void* targetProcessMemory = VirtualAllocEx(targetProcessHandle, nullptr, targetDllByteCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (targetProcessMemory == nullptr)
	{
		std::wcerr << L"VirtualAllocEx failed. Error: " << GetLastError() << L"\n";
		CloseHandle(targetProcessHandle);
		return -1;
	}

	if (!WriteProcessMemory(targetProcessHandle, targetProcessMemory, targetDll, targetDllByteCount, nullptr))
	{
		std::wcerr << L"WriteProcessMemory failed. Error: " << GetLastError() << L"\n";
		VirtualFreeEx(targetProcessHandle, targetProcessMemory, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return -1;
	}

	// ==============================

	HANDLE thread = CreateRemoteThread(targetProcessHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, targetProcessMemory, 0, nullptr);
	if (thread == nullptr)
	{
		std::wcerr << L"WFailed to create thread. Error: " << GetLastError() << L"\n";
		VirtualFreeEx(targetProcessHandle, targetProcessMemory, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return -1;
	}

	WaitForSingleObject(thread, INFINITE);

	DWORD threadExitCode = 0;
	GetExitCodeThread(thread, &threadExitCode);
	std::wcout << L"LoadLibraryW returned: 0x" << std::hex << threadExitCode << L"\n";

	VirtualFreeEx(targetProcessHandle, targetProcessMemory, 0, MEM_RELEASE);
	CloseHandle(targetProcessHandle);
	CloseHandle(thread);

	return 0;
}