#include "guard.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <random>
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <vector>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <wintrust.h>
#include <shobjidl.h>
#include <exdisp.h>
#include <shlobj.h>
#include <mutex>
#include <atomic>
#include <wbemidl.h>
#include <comutil.h>
#include <intrin.h>
#include <winnt.h>
#include <thread>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "advapi32.lib")

// GUID для COM-объектов
#ifndef CLSID_ShellWindows
constexpr GUID CLSID_ShellWindows = { 0x9BA05972, 0xF6A8, 0x11CF, { 0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39 } };
#endif

#ifndef IID_IShellWindows
constexpr GUID IID_IShellWindows = { 0x85CB6900, 0x4D95, 0x11CF, { 0x96, 0x0C, 0x00, 0x80, 0xC7, 0xF4, 0xEE, 0x85 } };
#endif

#ifndef IID_IWebBrowserApp
constexpr GUID IID_IWebBrowserApp = { 0x0002DF05, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
#endif

#ifndef WINTRUST_ACTION_GENERIC_VERIFY_V2
constexpr GUID WINTRUST_ACTION_GENERIC_VERIFY_V2 = { 0x00AAC56B, 0xCD44, 0x11D0, { 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
#endif

// Глобальные переменные
std::atomic<bool> debuggerDetected{ false };
std::vector<MemoryIntegrityData> protectedMemoryRegions;
std::mutex memoryRegionsMutex;
std::mutex debuggerMutex;
static PVOID dllNotificationCookie = NULL;

// NT-структуры и определения
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define ProcessBasicInformation 0
#define ProcessDebugObjectHandle 0x1E
#define ProcessCreationFlags 0x3
#define ThreadBasicInformation 0
#define SystemModuleInformation 11
#define SystemProcessInformation 5

typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union {
        ULONG CrossProcessFlags;
        struct {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
    };
    union {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SparePvoid0;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    ULONG_PTR ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_EX {
    ULONG ModulesCount;
    SYSTEM_MODULE_INFORMATION Modules[1];
} SYSTEM_MODULE_INFORMATION_EX, * PSYSTEM_MODULE_INFORMATION_EX;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
typedef VOID(NTAPI* PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG, PVOID, PVOID);
typedef NTSTATUS(NTAPI* LdrRegisterDllNotification_t)(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID*);
typedef NTSTATUS(NTAPI* LdrUnregisterDllNotification_t)(PVOID);

typedef struct _LDR_DLL_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG Size;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

// Утилитарные функции для работы со строками
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

// Функции логирования
void LogToFile(const std::string& message) {
    std::ofstream logFile("debug_log.txt", std::ios::app);
    if (logFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm time_info = {};
        localtime_s(&time_info, &now_c);
        char time_str[26];
        asctime_s(time_str, sizeof(time_str), &time_info);
        std::string time_str_cleaned = time_str;
        time_str_cleaned.erase(std::remove(time_str_cleaned.begin(), time_str_cleaned.end(), '\n'), time_str_cleaned.end());
        logFile << "[" << time_str_cleaned << "] " << message << std::endl;
        logFile.close();
    }
}

// Функции для работы с памятью
void CleanupMemoryIntegrity() {
    std::lock_guard<std::mutex> lock(memoryRegionsMutex);
    protectedMemoryRegions.clear();
    LogToFile("CleanupMemoryIntegrity: Memory regions cleared.");
}

void InitializeMemoryIntegrityCheck(void* memory, size_t size) {
    if (!memory || size == 0 || size > 1024 * 1024) {
        LogToFile("InitializeMemoryIntegrityCheck: Invalid memory or size: " + std::to_string(size));
        return;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(memory, size, PAGE_EXECUTE_READ, &oldProtect)) {
        LogToFile("InitializeMemoryIntegrityCheck: VirtualProtect failed, error: " + std::to_string(GetLastError()));
        return;
    }

    MemoryIntegrityData data;
    data.memory = memory;
    data.size = size;
    data.originalData.resize(size);
    memcpy(data.originalData.data(), memory, size);
    data.isProtected = true;
    data.crc = 0;

    std::lock_guard<std::mutex> lock(memoryRegionsMutex);
    protectedMemoryRegions.push_back(data);
    LogToFile("InitializeMemoryIntegrityCheck: Memory region protected, size: " + std::to_string(size));
}

bool CheckMemoryIntegrity() {
    std::lock_guard<std::mutex> lock(memoryRegionsMutex);
    for (auto& region : protectedMemoryRegions) {
        if (!region.isProtected) continue;

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQuery(region.memory, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) {
            LogToFile("CheckMemoryIntegrity: VirtualQuery failed or memory not committed for region at " + std::to_string((uintptr_t)region.memory));
            return false;
        }

        if (memcmp(region.memory, region.originalData.data(), region.size) != 0) {
            LogToFile("CheckMemoryIntegrity: Memory tampering detected at " + std::to_string((uintptr_t)region.memory));
            return false;
        }
    }
    LogToFile("CheckMemoryIntegrity: All memory regions intact.");
    return true;
}

// Функции для обнаружения отладчика
void ShowMessageAndExit() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 12); // RED
    LCID lcid = GetUserDefaultLCID();
    bool isRussian = (lcid == 1049);
    std::cout << (isRussian ? "Обнаружен отладчик!" : "Debugger detected!") << std::endl;
    LogToFile("ShowMessageAndExit called - exiting due to debugger detection.");
    Sleep(2000);
    exit(1);
}

bool CheckNtGlobalFlag() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (peb) {
        bool flagSet = (peb->NtGlobalFlag & 0x70) != 0;
        if (flagSet) {
            NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
            if (NtQueryInformationProcess) {
                PROCESS_BASIC_INFORMATION pbi = { 0 };
                NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
                if (NT_SUCCESS(status) && pbi.PebBaseAddress != peb) {
                    LogToFile("CheckNtGlobalFlag: PEB mismatch detected.");
                    return true;
                }
            }
            LogToFile("CheckNtGlobalFlag: NtGlobalFlag indicates debugger (0x70 set).");
            return true;
        }
    }
    LogToFile("CheckNtGlobalFlag: No debugger detected.");
    return false;
}

bool CheckHeapFlags() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (peb && peb->ProcessHeap) {
        DWORD* heapFlags = (DWORD*)((BYTE*)peb->ProcessHeap + 0x70);
        DWORD debugBits = (*heapFlags & (0x20 | 0x4000));
        if (debugBits != 0 && !IsDebuggerPresent() && !CheckRemoteDebugger()) {
            DWORD otherBits = (*heapFlags & ~(0x20 | 0x4000 | 0x5000));
            if (otherBits != 0) {
                LogToFile("CheckHeapFlags: Suspicious heap flags detected, but other bits set: " + std::to_string(otherBits));
                return false;
            }
            if (!(peb->NtGlobalFlag & 0x70)) {
                LogToFile("CheckHeapFlags: Debug bits set but NtGlobalFlag not set.");
                return false;
            }
        }
        if (debugBits != 0) {
            LogToFile("CheckHeapFlags: Debugger heap flags detected (0x20 or 0x4000 set).");
            return true;
        }
    }
    LogToFile("CheckHeapFlags: No debugger heap flags detected.");
    return false;
}

bool CheckIsDebuggerPresentDirect() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (peb) {
        bool result = peb->BeingDebugged != FALSE;
        LogToFile("CheckIsDebuggerPresentDirect: BeingDebugged = " + std::to_string(result));
        return result;
    }
    LogToFile("CheckIsDebuggerPresentDirect: PEB not accessible.");
    return false;
}

bool CheckDebugObject() {
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LogToFile("CheckDebugObject: NtQueryInformationProcess not found.");
        return false;
    }

    HANDLE hDebugObject = NULL;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(HANDLE), NULL);
    if (NT_SUCCESS(status) && hDebugObject != NULL) {
        LogToFile("CheckDebugObject: Debug object handle found.");
        return true;
    }
    LogToFile("CheckDebugObject: No debug object detected.");
    return false;
}

bool CheckCloseHandle() {
    BOOL result = FALSE;
    __try {
        CloseHandle((HANDLE)0xDEADBEEF);
        result = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = TRUE;
    }
    LogToFile("CheckCloseHandle: " + std::string(result ? "Exception thrown, debugger likely present." : "CloseHandle did not throw an exception."));
    return result;
}

bool CheckProcessDebugFlags() {
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LogToFile("CheckProcessDebugFlags: NtQueryInformationProcess not found.");
        return false;
    }

    DWORD debugFlags = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), NULL);
    if (NT_SUCCESS(status)) {
        bool result = debugFlags == 0;
        LogToFile("CheckProcessDebugFlags: DebugFlags = " + std::to_string(debugFlags) + ", result = " + std::to_string(result));
        return result;
    }
    LogToFile("CheckProcessDebugFlags: NtQueryInformationProcess failed, status: " + std::to_string(status));
    return false;
}

bool CheckParentProcess() {
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LogToFile("CheckParentProcess: NtQueryInformationProcess not found.");
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(status)) {
        LogToFile("CheckParentProcess: NtQueryInformationProcess failed, status: " + std::to_string(status));
        return false;
    }

    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pbi.InheritedFromUniqueProcessId);
    if (!hParent) {
        LogToFile("CheckParentProcess: OpenProcess failed for parent PID: " + std::to_string((DWORD)pbi.InheritedFromUniqueProcessId));
        return false;
    }

    wchar_t parentPath[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hParent, 0, parentPath, &size)) {
        std::wstring parentName = parentPath;
        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::towlower);
        CloseHandle(hParent);
        bool result = (parentName.find(L"explorer.exe") == std::wstring::npos &&
            parentName.find(L"cmd.exe") == std::wstring::npos &&
            parentName.find(L"powershell.exe") == std::wstring::npos);
        LogToFile("CheckParentProcess: Parent process: " + WStringToString(parentName) + ", result = " + std::to_string(result));
        return result;
    }
    CloseHandle(hParent);
    LogToFile("CheckParentProcess: QueryFullProcessImageNameW failed.");
    return false;
}

bool CheckOutputDebugStringAdvanced() {
    DWORD dwLastError = GetLastError();
    OutputDebugStringW(L"AntiDebugCheck");
    DWORD newError = GetLastError();
    if (newError != dwLastError) {
        LogToFile("CheckOutputDebugStringAdvanced: LastError changed from " + std::to_string(dwLastError) + " to " + std::to_string(newError));
        return true;
    }

    LARGE_INTEGER freq = { 0 }, t1 = { 0 }, t2 = { 0 };
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    OutputDebugStringW(L"AntiDebugCheck");
    QueryPerformanceCounter(&t2);

    LONGLONG elapsed = (t2.QuadPart - t1.QuadPart) * 1000000 / freq.QuadPart;
    if (elapsed > 1000) {
        LogToFile("CheckOutputDebugStringAdvanced: Timing delay detected, elapsed: " + std::to_string(elapsed) + " microseconds");
        return true;
    }
    LogToFile("CheckOutputDebugStringAdvanced: No debugger detected, elapsed: " + std::to_string(elapsed) + " microseconds");
    return false;
}

bool CheckRemoteDebugger() {
    BOOL bDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent);
    LogToFile("CheckRemoteDebugger: Debugger present = " + std::to_string(bDebuggerPresent != FALSE));
    return bDebuggerPresent != FALSE;
}

bool CheckDebugPort() {
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LogToFile("CheckDebugPort: NtQueryInformationProcess not found.");
        return false;
    }

    HANDLE debugPort = NULL;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
    if (NT_SUCCESS(status) && debugPort != NULL) {
        LogToFile("CheckDebugPort: Debug port detected.");
        return true;
    }
    LogToFile("CheckDebugPort: No debug port detected.");
    return false;
}

bool CheckSoftwareBreakpointsAdvanced() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        LogToFile("CheckSoftwareBreakpointsAdvanced: ntdll.dll not found.");
        return false;
    }

    FARPROC funcAddr = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!funcAddr) {
        LogToFile("CheckSoftwareBreakpointsAdvanced: NtQueryInformationProcess not found.");
        return false;
    }

    BYTE* bytes = (BYTE*)funcAddr;
    for (size_t i = 0; i < 10; i++) {
        if (bytes[i] == 0xCC) {
            LogToFile("CheckSoftwareBreakpointsAdvanced: Software breakpoint (0xCC) detected at NtQueryInformationProcess.");
            return true;
        }
    }
    LogToFile("CheckSoftwareBreakpointsAdvanced: No software breakpoints detected.");
    return false;
}

bool CheckHardwareBreakpointsAdvanced() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        LogToFile("CheckHardwareBreakpointsAdvanced: GetThreadContext failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0xFF)) {
        LogToFile("CheckHardwareBreakpointsAdvanced: Hardware breakpoints detected (Dr0-Dr3 or Dr7 set).");
        return true;
    }
    LogToFile("CheckHardwareBreakpointsAdvanced: No hardware breakpoints detected.");
    return false;
}

bool CheckExceptions() {
    if (IsDebuggerPresent()) {
        LogToFile("CheckExceptions: IsDebuggerPresent returned true.");
        return true;
    }

    BOOL exceptionHandled = FALSE;
    __try {
        RaiseException(0x40010006, 0, 0, NULL);
        exceptionHandled = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionHandled = TRUE;
    }

    if (exceptionHandled && !IsDebuggerPresent()) {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0xFF)) {
                LogToFile("CheckExceptions: Hardware breakpoints detected after exception.");
                return true;
            }
        }
    }
    LogToFile("CheckExceptions: Result = " + std::to_string(exceptionHandled));
    return exceptionHandled;
}

bool CheckAssemblyInstructions() {
    if (IsDebuggerPresent()) {
        LogToFile("CheckAssemblyInstructions: IsDebuggerPresent returned true.");
        return true;
    }

    BYTE int3Code[] = { 0xCC, 0xC3 };
    void* execMem = VirtualAlloc(NULL, sizeof(int3Code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        LogToFile("CheckAssemblyInstructions: VirtualAlloc failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    memcpy(execMem, int3Code, sizeof(int3Code));

    BOOL detected = FALSE;
    DWORD exceptionCode = 0;
    __try {
        typedef void (*Int3Func)();
        Int3Func func = (Int3Func)execMem;
        func();
        detected = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionCode = GetExceptionCode();
        if (exceptionCode == EXCEPTION_BREAKPOINT) {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), &ctx)) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0xFF)) {
                    detected = TRUE;
                }
            }
            detected = FALSE;
        }
        else {
            detected = TRUE;
        }
    }

    if (!VirtualFree(execMem, 0, MEM_RELEASE)) {
        LogToFile("CheckAssemblyInstructions: VirtualFree failed, error: " + std::to_string(GetLastError()));
    }
    LogToFile("CheckAssemblyInstructions: Result = " + std::to_string(detected) + ", Exception code = " + std::to_string(exceptionCode));
    return detected;
}

bool CheckTimingAdvanced() {
    LARGE_INTEGER freq = { 0 }, t1 = { 0 }, t2 = { 0 };
    QueryPerformanceFrequency(&freq);

    const int iterations = 10;
    const int loop_count = 200000;
    LONGLONG base_threshold = 0;
    std::vector<LONGLONG> timings;

    for (int i = 0; i < 3; i++) {
        QueryPerformanceCounter(&t1);
        volatile double dummy = 0.0;
        for (volatile int j = 0; j < loop_count; j++) {
            dummy += j * 1.1;
        }
        QueryPerformanceCounter(&t2);
        base_threshold += (t2.QuadPart - t1.QuadPart) * 1000000 / freq.QuadPart;
        Sleep(10);
    }
    base_threshold /= 3;
    LONGLONG max_threshold = base_threshold * 2;

    int suspicious_count = 0;
    for (int i = 0; i < iterations; i++) {
        QueryPerformanceCounter(&t1);
        volatile double dummy = 0.0;
        for (volatile int j = 0; j < loop_count; j++) {
            dummy += j * 1.1;
        }
        QueryPerformanceCounter(&t2);

        LONGLONG elapsed = (t2.QuadPart - t1.QuadPart) * 1000000 / freq.QuadPart;
        timings.push_back(elapsed);
        if (elapsed > max_threshold) {
            suspicious_count++;
        }
        Sleep(10);
    }

    LogToFile("CheckTimingAdvanced: Base threshold = " + std::to_string(base_threshold) + ", Max threshold = " + std::to_string(max_threshold) + ", Suspicious count = " + std::to_string(suspicious_count));
    return suspicious_count >= 6;
}

bool CheckForDebuggerProcesses() {
    std::vector<std::wstring> debuggerProcesses = {
        L"x64dbg.exe", L"x32dbg.exe", L"ida.exe", L"ida64.exe",
        L"ollydbg.exe", L"procmon.exe", L"procexp.exe", L"windbg.exe"
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogToFile("CheckForDebuggerProcesses: CreateToolhelp32Snapshot failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::wstring exeName = pe32.szExeFile;
            std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);
            for (const auto& debugger : debuggerProcesses) {
                if (exeName == debugger) {
                    LogToFile("CheckForDebuggerProcesses: Debugger process found: " + WStringToString(exeName));
                    found = true;
                    break;
                }
            }
        } while (!found && Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    if (!found) {
        LogToFile("CheckForDebuggerProcesses: No debugger processes found.");
    }
    return found;
}

bool CheckForDebuggerStrings() {
    std::vector<std::wstring> debuggerStrings = {
        L"x64dbg", L"x32dbg", L"ida", L"ollydbg", L"procmon", L"procexp", L"windbg"
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogToFile("CheckForDebuggerStrings: CreateToolhelp32Snapshot failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                wchar_t processPath[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                    std::wstring path = processPath;
                    std::transform(path.begin(), path.end(), path.begin(), ::towlower);
                    for (const auto& str : debuggerStrings) {
                        if (path.find(str) != std::wstring::npos) {
                            LogToFile("CheckForDebuggerStrings: Debugger string found in process path: " + WStringToString(path));
                            found = true;
                            break;
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        } while (!found && Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    if (!found) {
        LogToFile("CheckForDebuggerStrings: No debugger strings found in process paths.");
    }
    return found;
}

bool CheckForActiveDebuggerWindows() {
    std::vector<std::wstring> debuggerWindowClasses = {
        L"OLLYDBG", L"WinDbgFrameClass", L"ID"
    };

    for (const auto& className : debuggerWindowClasses) {
        if (FindWindowW(className.c_str(), NULL) != NULL) {
            LogToFile("CheckForActiveDebuggerWindows: Debugger window found: " + WStringToString(className));
            return true;
        }
    }
    LogToFile("CheckForActiveDebuggerWindows: No debugger windows found.");
    return false;
}

bool CheckForDebuggerDrivers() {
    std::vector<std::wstring> debuggerDrivers = {
        L"ida", L"x64dbg", L"olly"
    };

    HANDLE hDevice = NULL;
    for (const auto& driver : debuggerDrivers) {
        std::wstring devicePath = L"\\\\.\\" + driver;
        hDevice = CreateFileW(devicePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            LogToFile("CheckForDebuggerDrivers: Debugger driver found: " + WStringToString(driver));
            CloseHandle(hDevice);
            return true;
        }
    }
    LogToFile("CheckForDebuggerDrivers: No debugger drivers found.");
    return false;
}

bool CheckForFunctionHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        LogToFile("CheckForFunctionHooks: ntdll.dll not found.");
        return false;
    }

    FARPROC funcAddr = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!funcAddr) {
        LogToFile("CheckForFunctionHooks: NtQueryInformationProcess not found.");
        return false;
    }

    BYTE* bytes = (BYTE*)funcAddr;
    if (bytes[0] == 0xE9 || bytes[0] == 0xFF || bytes[0] == 0xEB) {
        LogToFile("CheckForFunctionHooks: Hook detected in NtQueryInformationProcess (first byte: " + std::to_string(bytes[0]) + ").");
        return true;
    }
    LogToFile("CheckForFunctionHooks: No hooks detected in NtQueryInformationProcess.");
    return false;
}

bool CheckForInjectedModules() {
    std::vector<std::wstring> suspiciousModules = {
        L"x64dbg.dll", L"ida.dll", L"frida.dll", L"ghinjector.dll", L"scylla_hide.dll",
        L"extremeinjector.dll", L"x64gui.dll", L"titanengine.dll", L"scylla.dll",
        L"x64_dbg.dll", L"x64bridge.dll", L"XEDParse.dll", L"dbghelp.dll", L"x64_bridge.dll",
        L"x32_bridge.dll", L"x32_dbg.dll", L"x32bridge.dll", L"x32dbg.dll", L"x32gui.dll",
        L"ResourceHacker.exe", L"ResourceHacker.ini"
    };

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    HANDLE hProcess = GetCurrentProcess();
    if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL) {
        LogToFile("CheckForInjectedModules: GetCurrentProcess failed.");
        return false;
    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                std::wstring modPath = szModName;
                std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::towlower);
                for (const auto& suspicious : suspiciousModules) {
                    if (modPath.find(suspicious) != std::wstring::npos) {
                        LogToFile("CheckForInjectedModules: Suspicious module found: " + WStringToString(modPath));
                        return true;
                    }
                }
            }
        }
    }
    LogToFile("CheckForInjectedModules: No suspicious modules found.");
    return false;
}

bool CheckForVirtualProtectAbuse() {
    static DWORD protectCallCount = 0;
    static LARGE_INTEGER lastCheckTime = { 0 };

    LARGE_INTEGER currentTime = { 0 }, freq = { 0 };
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&currentTime);

    if ((currentTime.QuadPart - lastCheckTime.QuadPart) * 1000000 / freq.QuadPart >= 5000000) {
        if (protectCallCount > 500) {
            LogToFile("CheckForVirtualProtectAbuse: Excessive VirtualProtect calls detected: " + std::to_string(protectCallCount));
            return true;
        }
        protectCallCount = 0;
        lastCheckTime = currentTime;
    }

    DWORD oldProtect = 0;
    if (VirtualProtect(&CheckForVirtualProtectAbuse, sizeof(void*), PAGE_EXECUTE_READ, &oldProtect)) {
        protectCallCount++;
        VirtualProtect(&CheckForVirtualProtectAbuse, sizeof(void*), oldProtect, &oldProtect);
    }

    LogToFile("CheckForVirtualProtectAbuse: Call count = " + std::to_string(protectCallCount));
    return false;
}

static bool CheckGlobalFlagsClearInProcess() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        LogToFile("CheckGlobalFlagsClearInProcess: GetModuleHandle failed.");
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LogToFile("CheckGlobalFlagsClearInProcess: Invalid DOS signature.");
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LogToFile("CheckGlobalFlagsClearInProcess: Invalid NT signature.");
        return false;
    }

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress == 0) {
        LogToFile("CheckGlobalFlagsClearInProcess: Load config directory not present.");
        return false;
    }

    PIMAGE_LOAD_CONFIG_DIRECTORY loadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (!loadConfig || loadConfig->Size < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)) {
        LogToFile("CheckGlobalFlagsClearInProcess: Load config directory not found or invalid size.");
        return false;
    }

    if (loadConfig->GlobalFlagsClear != 0) {
        LogToFile("CheckGlobalFlagsClearInProcess: GlobalFlagsClear set to " + std::to_string(loadConfig->GlobalFlagsClear));
        return true;
    }
    LogToFile("CheckGlobalFlagsClearInProcess: No suspicious GlobalFlagsClear settings.");
    return false;
}

bool CheckGlobalFlagsClearInFile() {
    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        LogToFile("CheckGlobalFlagsClearInFile: GetModuleFileNameW failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogToFile("CheckGlobalFlagsClearInFile: CreateFileW failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        LogToFile("CheckGlobalFlagsClearInFile: CreateFileMappingW failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    PBYTE pBase = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        LogToFile("CheckGlobalFlagsClearInFile: MapViewOfFile failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        LogToFile("CheckGlobalFlagsClearInFile: Invalid DOS signature in file.");
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        LogToFile("CheckGlobalFlagsClearInFile: Invalid NT signature in file.");
        return false;
    }

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress == 0) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        LogToFile("CheckGlobalFlagsClearInFile: Load config directory not present in file.");
        return false;
    }

    PIMAGE_LOAD_CONFIG_DIRECTORY loadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (!loadConfig || loadConfig->Size < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        LogToFile("CheckGlobalFlagsClearInFile: Load config directory not found or invalid size in file.");
        return false;
    }

    bool result = (loadConfig->GlobalFlagsClear != 0);
    if (result) {
        LogToFile("CheckGlobalFlagsClearInFile: GlobalFlagsClear set to " + std::to_string(loadConfig->GlobalFlagsClear) + " in file.");
    }
    else {
        LogToFile("CheckGlobalFlagsClearInFile: No suspicious GlobalFlagsClear settings in file.");
    }

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return result;
}

bool CheckForDebuggerRegistryKeys() {
    std::vector<std::wstring> debuggerKeys = {
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    };

    for (const auto& keyPath : debuggerKeys) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subKeyCount = 0;
            if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (subKeyCount > 0) {
                    for (DWORD i = 0; i < subKeyCount; i++) {
                        wchar_t subKeyName[MAX_PATH] = { 0 };
                        DWORD subKeyNameSize = MAX_PATH;
                        if (RegEnumKeyExW(hKey, i, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                            HKEY hSubKey = NULL;
                            std::wstring fullSubKeyPath = keyPath + L"\\" + subKeyName;
                            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullSubKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                                wchar_t debuggerValue[MAX_PATH] = { 0 };
                                DWORD dataSize = sizeof(debuggerValue);
                                if (RegQueryValueExW(hSubKey, L"Debugger", NULL, NULL, (LPBYTE)debuggerValue, &dataSize) == ERROR_SUCCESS) {
                                    LogToFile("CheckForDebuggerRegistryKeys: Debugger registry key found: " + WStringToString(fullSubKeyPath) + ", value: " + WStringToString(debuggerValue));
                                    RegCloseKey(hSubKey);
                                    RegCloseKey(hKey);
                                    return true;
                                }
                                RegCloseKey(hSubKey);
                            }
                        }
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
    LogToFile("CheckForDebuggerRegistryKeys: No debugger registry keys found.");
    return false;
}

bool CheckForIFEODebugger() {
    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        LogToFile("CheckForIFEODebugger: GetModuleFileNameW failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    std::wstring exeName = PathFindFileNameW(exePath);
    std::wstring ifeoPath = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + exeName;

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeoPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t debuggerValue[MAX_PATH] = { 0 };
        DWORD dataSize = sizeof(debuggerValue);
        if (RegQueryValueExW(hKey, L"Debugger", NULL, NULL, (LPBYTE)debuggerValue, &dataSize) == ERROR_SUCCESS) {
            LogToFile("CheckForIFEODebugger: IFEO Debugger found for " + WStringToString(exeName) + ": " + WStringToString(debuggerValue));
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    LogToFile("CheckForIFEODebugger: No IFEO Debugger found for " + WStringToString(exeName));
    return false;
}

bool CheckForExplorerDebuggerFolder() {
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        LogToFile("CheckForExplorerDebuggerFolder: CoInitialize failed, HRESULT: " + std::to_string(hr));
        return false;
    }

    IShellWindows* pShellWindows = NULL;
    hr = CoCreateInstance(CLSID_ShellWindows, NULL, CLSCTX_ALL, IID_IShellWindows, (void**)&pShellWindows);
    if (FAILED(hr) || !pShellWindows) {
        LogToFile("CheckForExplorerDebuggerFolder: CoCreateInstance for IShellWindows failed, HRESULT: " + std::to_string(hr));
        CoUninitialize();
        return false;
    }

    long count = 0;
    hr = pShellWindows->get_Count(&count);
    if (FAILED(hr)) {
        pShellWindows->Release();
        CoUninitialize();
        LogToFile("CheckForExplorerDebuggerFolder: get_Count failed, HRESULT: " + std::to_string(hr));
        return false;
    }

    bool found = false;
    for (long i = 0; i < count && !found; i++) {
        VARIANT v = { VT_I4 };
        v.lVal = i;
        IDispatch* pDisp = NULL;
        hr = pShellWindows->Item(v, &pDisp);
        if (SUCCEEDED(hr) && pDisp) {
            IWebBrowserApp* pBrowser = NULL;
            hr = pDisp->QueryInterface(IID_IWebBrowserApp, (void**)&pBrowser);
            if (SUCCEEDED(hr) && pBrowser) {
                BSTR location = NULL;
                hr = pBrowser->get_LocationURL(&location);
                if (SUCCEEDED(hr) && location) {
                    std::wstring url = location;
                    SysFreeString(location);
                    std::transform(url.begin(), url.end(), url.begin(), ::towlower);
                    if (url.find(L"debugger") != std::wstring::npos || url.find(L"debug") != std::wstring::npos) {
                        LogToFile("CheckForExplorerDebuggerFolder: Suspicious Explorer folder found: " + WStringToString(url));
                        found = true;
                    }
                }
                pBrowser->Release();
            }
            pDisp->Release();
        }
    }

    pShellWindows->Release();
    CoUninitialize();
    if (!found) {
        LogToFile("CheckForExplorerDebuggerFolder: No suspicious Explorer folders found.");
    }
    return found;
}

bool CheckNoDebugInherit() {
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LogToFile("CheckNoDebugInherit: NtQueryInformationProcess not found.");
        return false;
    }

    ULONG creationFlags = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessCreationFlags, &creationFlags, sizeof(creationFlags), NULL);
    if (!NT_SUCCESS(status)) {
        LogToFile("CheckNoDebugInherit: NtQueryInformationProcess failed, status: " + std::to_string(status));
        return false;
    }

    bool result = (creationFlags & 0x400) != 0; // DEBUG_PROCESS_NOT_INHERITED
    LogToFile("CheckNoDebugInherit: CreationFlags = " + std::to_string(creationFlags) + ", result = " + std::to_string(result));
    return result;
}

bool CheckExceptionCount() {
    static DWORD exceptionCount = 0;
    static LARGE_INTEGER lastCheckTime = { 0 };

    LARGE_INTEGER currentTime = { 0 }, freq = { 0 };
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&currentTime);

    if ((currentTime.QuadPart - lastCheckTime.QuadPart) * 1000000 / freq.QuadPart >= 10000000) {
        if (exceptionCount > 50) {
            LogToFile("CheckExceptionCount: Excessive exceptions detected: " + std::to_string(exceptionCount));
            return true;
        }
        exceptionCount = 0;
        lastCheckTime = currentTime;
    }

    BOOL exceptionThrown = FALSE;
    __try {
        RaiseException(0xE0000001, 0, 0, NULL);
        exceptionThrown = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionCount++;
        exceptionThrown = TRUE;
    }

    LogToFile("CheckExceptionCount: Exception thrown = " + std::to_string(exceptionThrown) + ", Count = " + std::to_string(exceptionCount));
    return false;
}

bool CheckForAnalysisToolsViaWMI() {
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        LogToFile("CheckForAnalysisToolsViaWMI: CoInitialize failed, HRESULT: " + std::to_string(hr));
        return false;
    }

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        LogToFile("CheckForAnalysisToolsViaWMI: CoCreateInstance for IWbemLocator failed, HRESULT: " + std::to_string(hr));
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    hr = pLoc->ConnectServer(bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    SysFreeString(bstrNamespace);
    pLoc->Release();
    if (FAILED(hr)) {
        LogToFile("CheckForAnalysisToolsViaWMI: ConnectServer failed, HRESULT: " + std::to_string(hr));
        CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        pSvc->Release();
        CoUninitialize();
        LogToFile("CheckForAnalysisToolsViaWMI: CoSetProxyBlanket failed, HRESULT: " + std::to_string(hr));
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    BSTR bstrQuery = SysAllocString(L"SELECT * FROM Win32_Process");
    BSTR bstrWQL = SysAllocString(L"WQL");
    hr = pSvc->ExecQuery(bstrWQL, bstrQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    SysFreeString(bstrQuery);
    SysFreeString(bstrWQL);
    if (FAILED(hr)) {
        pSvc->Release();
        CoUninitialize();
        LogToFile("CheckForAnalysisToolsViaWMI: ExecQuery failed, HRESULT: " + std::to_string(hr));
        return false;
    }

    std::vector<std::wstring> analysisTools = {
        L"x64dbg.exe", L"x32dbg.exe", L"ida.exe", L"ida64.exe",
        L"ollydbg.exe", L"procmon.exe", L"procexp.exe",
        L"windbg.exe"
    };

    bool found = false;
    IWbemClassObject* pObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn);
        if (uReturn == 0) break;

        VARIANT vtProp;
        VariantInit(&vtProp);
        hr = pObj->Get(L"Name", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            std::wstring processName = vtProp.bstrVal;
            std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
            for (const auto& tool : analysisTools) {
                if (processName == tool) {
                    LogToFile("CheckForAnalysisToolsViaWMI: Analysis tool found: " + WStringToString(processName));
                    found = true;
                    break;
                }
            }
        }
        VariantClear(&vtProp);
        pObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    CoUninitialize();
    if (!found) {
        LogToFile("CheckForAnalysisToolsViaWMI: No analysis tools found.");
    }
    return found;
}

bool CheckForSystemCallHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        LogToFile("CheckForSystemCallHooks: ntdll.dll not found.");
        return false;
    }

    std::vector<std::string> sysCalls = {
        "NtQuerySystemInformation",
        "NtQueryInformationProcess",
        "NtCreateFile",
        "NtOpenProcess"
    };

    for (const auto& sysCall : sysCalls) {
        FARPROC funcAddr = GetProcAddress(hNtdll, sysCall.c_str());
        if (!funcAddr) {
            LogToFile("CheckForSystemCallHooks: " + sysCall + " not found.");
            continue;
        }

        BYTE* bytes = (BYTE*)funcAddr;
        if (bytes[0] == 0xE9 || bytes[0] == 0xFF || bytes[0] == 0xEB) {
            LogToFile("CheckForSystemCallHooks: Hook detected in " + sysCall + " (first byte: " + std::to_string(bytes[0]) + ").");
            return true;
        }
    }
    LogToFile("CheckForSystemCallHooks: No system call hooks detected.");
    return false;
}

bool CheckForThreadHiding() {
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        LogToFile("CheckForThreadHiding: NtQuerySystemInformation not found.");
        return false;
    }

    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        LogToFile("CheckForThreadHiding: VirtualAlloc failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForThreadHiding: NtQuerySystemInformation failed, status: " + std::to_string(status));
        return false;
    }

    DWORD currentProcessId = GetCurrentProcessId();
    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    bool foundProcess = false;
    while (processInfo->NextEntryOffset) {
        if (processInfo->UniqueProcessId == (HANDLE)(DWORD_PTR)currentProcessId) {
            foundProcess = true;
            break;
        }
        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)processInfo + processInfo->NextEntryOffset);
    }

    if (!foundProcess) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForThreadHiding: Current process not found in system process list - possible hiding.");
        return true;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForThreadHiding: CreateToolhelp32Snapshot failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    THREADENTRY32 te32 = { sizeof(te32) };
    DWORD threadCountSnapshot = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentProcessId) {
                threadCountSnapshot++;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    if (threadCountSnapshot != processInfo->NumberOfThreads) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForThreadHiding: Thread count mismatch - System: " + std::to_string(processInfo->NumberOfThreads) + ", Snapshot: " + std::to_string(threadCountSnapshot));
        return true;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    LogToFile("CheckForThreadHiding: No thread hiding detected.");
    return false;
}

bool CheckForModuleHiding() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) {
        LogToFile("CheckForModuleHiding: PEB or Ldr not accessible.");
        return false;
    }

    std::vector<std::wstring> pebModules;
    PLIST_ENTRY moduleList = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = moduleList->Flink;
    while (entry != moduleList) {
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)((PBYTE)entry - sizeof(LIST_ENTRY));
        if (module->BaseDllName.Buffer) {
            std::wstring dllName = module->BaseDllName.Buffer;
            std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::towlower);
            pebModules.push_back(dllName);
        }
        entry = entry->Flink;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    HANDLE hProcess = GetCurrentProcess();
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        LogToFile("CheckForModuleHiding: EnumProcessModules failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    std::vector<std::wstring> enumModules;
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        wchar_t szModName[MAX_PATH] = { 0 };
        if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
            std::wstring modName = PathFindFileNameW(szModName);
            std::transform(modName.begin(), modName.end(), modName.begin(), ::towlower);
            enumModules.push_back(modName);
        }
    }

    for (const auto& mod : enumModules) {
        if (std::find(pebModules.begin(), pebModules.end(), mod) == pebModules.end()) {
            LogToFile("CheckForModuleHiding: Module " + WStringToString(mod) + " not found in PEB - possible hiding.");
            return true;
        }
    }

    LogToFile("CheckForModuleHiding: No module hiding detected.");
    return false;
}

bool CheckForMemoryPatches() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        LogToFile("CheckForMemoryPatches: ntdll.dll not found.");
        return false;
    }

    FARPROC funcAddr = GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!funcAddr) {
        LogToFile("CheckForMemoryPatches: NtQuerySystemInformation not found.");
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (!VirtualQuery(funcAddr, &mbi, sizeof(mbi))) {
        LogToFile("CheckForMemoryPatches: VirtualQuery failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    if (mbi.Protect & (PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE)) {
        LogToFile("CheckForMemoryPatches: Suspicious memory protection detected for NtQuerySystemInformation: " + std::to_string(mbi.Protect));
        return true;
    }

    LogToFile("CheckForMemoryPatches: No memory patches detected.");
    return false;
}

bool CheckForFileSystemRedirection() {
    // Функция удалена, так как относится к спуфингу
    LogToFile("CheckForFileSystemRedirection: Function not implemented (spoofing-related).");
    return false;
}

bool CheckForDriverSignatureEnforcement() {
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        LogToFile("CheckForDriverSignatureEnforcement: NtQuerySystemInformation not found.");
        return false;
    }

    SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
    NTSTATUS status = NtQuerySystemInformation(103, &ci, sizeof(ci), NULL);
    if (!NT_SUCCESS(status)) {
        LogToFile("CheckForDriverSignatureEnforcement: NtQuerySystemInformation failed, status: " + std::to_string(status));
        return false;
    }

    bool result = (ci.CodeIntegrityOptions & 0x2) == 0; // 0x2 = CODEINTEGRITY_OPTION_ENABLED
    LogToFile("CheckForDriverSignatureEnforcement: CodeIntegrityOptions = " + std::to_string(ci.CodeIntegrityOptions) + ", result = " + std::to_string(result));
    return result;
}

bool CheckForTestSigningMode() {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        LogToFile("CheckForTestSigningMode: RegOpenKeyExW failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    DWORD testSignValue = 0;
    DWORD dataSize = sizeof(DWORD);
    bool result = false;
    if (RegQueryValueExW(hKey, L"BcdLibraryBoolean_AllowPrereleaseSignatures", NULL, NULL, (LPBYTE)&testSignValue, &dataSize) == ERROR_SUCCESS) {
        result = (testSignValue != 0);
        LogToFile("CheckForTestSigningMode: Test signing mode = " + std::to_string(testSignValue));
    }
    else {
        LogToFile("CheckForTestSigningMode: Test signing mode not set or error reading registry.");
    }

    RegCloseKey(hKey);
    return result;
}

bool CheckForUnsignedDrivers() {
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        LogToFile("CheckForUnsignedDrivers: NtQuerySystemInformation not found.");
        return false;
    }

    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        LogToFile("CheckForUnsignedDrivers: VirtualAlloc failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForUnsignedDrivers: NtQuerySystemInformation failed, status: " + std::to_string(status));
        return false;
    }

    PSYSTEM_MODULE_INFORMATION_EX moduleInfo = (PSYSTEM_MODULE_INFORMATION_EX)buffer;
    bool foundUnsigned = false;
    for (ULONG i = 0; i < moduleInfo->ModulesCount; i++) {
        std::string moduleName = moduleInfo->Modules[i].ImageName;
        std::wstring wModuleName = StringToWString(moduleName);

        WINTRUST_FILE_INFO fileData = { 0 };
        fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileData.pcwszFilePath = wModuleName.c_str();

        WINTRUST_DATA winTrustData = { 0 };
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.pFile = &fileData;

        LONG verifyStatus = WinVerifyTrust(NULL, (GUID*)&WINTRUST_ACTION_GENERIC_VERIFY_V2, &winTrustData);
        if (verifyStatus != ERROR_SUCCESS) {
            LogToFile("CheckForUnsignedDrivers: Unsigned driver found: " + moduleName);
            foundUnsigned = true;
        }

        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, (GUID*)&WINTRUST_ACTION_GENERIC_VERIFY_V2, &winTrustData);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    if (!foundUnsigned) {
        LogToFile("CheckForUnsignedDrivers: No unsigned drivers found.");
    }
    return foundUnsigned;
}

bool CheckForDriverHiding() {
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        LogToFile("CheckForDriverHiding: NtQuerySystemInformation not found.");
        return false;
    }

    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        LogToFile("CheckForDriverHiding: VirtualAlloc failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForDriverHiding: NtQuerySystemInformation failed, status: " + std::to_string(status));
        return false;
    }

    PSYSTEM_MODULE_INFORMATION_EX moduleInfo = (PSYSTEM_MODULE_INFORMATION_EX)buffer;
    std::vector<std::string> expectedDrivers = { "ntoskrnl.exe", "hal.dll", "win32k.sys" };
    bool foundExpected = false;

    for (ULONG i = 0; i < moduleInfo->ModulesCount; i++) {
        std::string moduleName = moduleInfo->Modules[i].ImageName;
        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
        for (const auto& expected : expectedDrivers) {
            if (moduleName.find(expected) != std::string::npos) {
                foundExpected = true;
                break;
            }
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    if (!foundExpected) {
        LogToFile("CheckForDriverHiding: Expected drivers not found - possible driver hiding.");
        return true;
    }
    LogToFile("CheckForDriverHiding: No driver hiding detected.");
    return false;
}

bool CheckForDriverHooks() {
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        LogToFile("CheckForDriverHooks: NtQuerySystemInformation not found.");
        return false;
    }

    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        LogToFile("CheckForDriverHooks: VirtualAlloc failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForDriverHooks: NtQuerySystemInformation failed, status: " + std::to_string(status));
        return false;
    }

    PSYSTEM_MODULE_INFORMATION_EX moduleInfo = (PSYSTEM_MODULE_INFORMATION_EX)buffer;
    bool foundHook = false;

    for (ULONG i = 0; i < moduleInfo->ModulesCount; i++) {
        PVOID base = moduleInfo->Modules[i].Base;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (VirtualQuery(base, &mbi, sizeof(mbi))) {
            if (mbi.Protect & (PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE)) {
                LogToFile("CheckForDriverHooks: Suspicious memory protection for driver: " + std::string(moduleInfo->Modules[i].ImageName));
                foundHook = true;
                break;
            }
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    if (!foundHook) {
        LogToFile("CheckForDriverHooks: No driver hooks detected.");
    }
    return foundHook;
}

bool CheckForDriverInjection() {
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        LogToFile("CheckForDriverInjection: NtQuerySystemInformation not found.");
        return false;
    }

    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        LogToFile("CheckForDriverInjection: VirtualAlloc failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        LogToFile("CheckForDriverInjection: NtQuerySystemInformation failed, status: " + std::to_string(status));
        return false;
    }

    PSYSTEM_MODULE_INFORMATION_EX moduleInfo = (PSYSTEM_MODULE_INFORMATION_EX)buffer;
    std::vector<std::string> suspiciousDrivers = { "cheat", "hack", "inject" };
    bool foundSuspicious = false;

    for (ULONG i = 0; i < moduleInfo->ModulesCount; i++) {
        std::string moduleName = moduleInfo->Modules[i].ImageName;
        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
        for (const auto& suspicious : suspiciousDrivers) {
            if (moduleName.find(suspicious) != std::string::npos) {
                LogToFile("CheckForDriverInjection: Suspicious driver found: " + moduleName);
                foundSuspicious = true;
                break;
            }
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    if (!foundSuspicious) {
        LogToFile("CheckForDriverInjection: No suspicious drivers found.");
    }
    return foundSuspicious;
}

bool CheckForAPCInjection() {
    NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInformationThread) {
        LogToFile("CheckForAPCInjection: NtQueryInformationThread not found.");
        return false;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogToFile("CheckForAPCInjection: CreateToolhelp32Snapshot failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    THREADENTRY32 te32 = { sizeof(te32) };
    DWORD currentProcessId = GetCurrentProcessId();
    bool foundSuspicious = false;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentProcessId) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    THREAD_BASIC_INFORMATION tbi = { 0 };
                    NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
                    if (NT_SUCCESS(status)) {
                        PVOID teb = tbi.TebBaseAddress;
                        if (teb) {
                            PVOID alertable = (PVOID)((PBYTE)teb + 0x48); // TEB::ThreadLocalStoragePointer + offset to Alertable
                            BYTE alertableValue = 0;
                            SIZE_T bytesRead = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), alertable, &alertableValue, sizeof(BYTE), &bytesRead) && bytesRead == sizeof(BYTE)) {
                                if (alertableValue != 0) {
                                    LogToFile("CheckForAPCInjection: Thread " + std::to_string(te32.th32ThreadID) + " is alertable - possible APC injection.");
                                    foundSuspicious = true;
                                }
                            }
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (!foundSuspicious && Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    if (!foundSuspicious) {
        LogToFile("CheckForAPCInjection: No APC injection detected.");
    }
    return foundSuspicious;
}

bool CheckForHookInjection() {
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    HANDLE hProcess = GetCurrentProcess();
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        LogToFile("CheckForHookInjection: EnumProcessModules failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    bool foundHook = false;
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        MODULEINFO modInfo = { 0 };
        if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
            BYTE* entryPoint = (BYTE*)modInfo.EntryPoint;
            if (entryPoint) {
                if (entryPoint[0] == 0xE9 || entryPoint[0] == 0xFF || entryPoint[0] == 0xEB) {
                    wchar_t szModName[MAX_PATH] = { 0 };
                    GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t));
                    LogToFile("CheckForHookInjection: Hook detected in module " + WStringToString(szModName) + " at entry point.");
                    foundHook = true;
                    break;
                }
            }
        }
    }

    if (!foundHook) {
        LogToFile("CheckForHookInjection: No hook injections detected.");
    }
    return foundHook;
}

bool CheckForRemoteThreadInjection() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogToFile("CheckForRemoteThreadInjection: CreateToolhelp32Snapshot failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    THREADENTRY32 te32 = { sizeof(te32) };
    DWORD currentProcessId = GetCurrentProcessId();
    bool foundSuspicious = false;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentProcessId) {
                HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    PVOID startAddress = NULL;
                    NTSTATUS status = NtQueryInformationThread(hThread, 9, &startAddress, sizeof(startAddress), NULL);
                    if (NT_SUCCESS(status) && startAddress) {
                        MEMORY_BASIC_INFORMATION mbi = { 0 };
                        if (VirtualQuery(startAddress, &mbi, sizeof(mbi))) {
                            if (mbi.AllocationBase != GetModuleHandle(NULL)) {
                                LogToFile("CheckForRemoteThreadInjection: Suspicious thread start address in thread " + std::to_string(te32.th32ThreadID));
                                foundSuspicious = true;
                            }
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (!foundSuspicious && Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    if (!foundSuspicious) {
        LogToFile("CheckForRemoteThreadInjection: No remote thread injections detected.");
    }
    return foundSuspicious;
}

bool CheckThreadIntegrity(HANDLE hThread) {
    if (!hThread || hThread == INVALID_HANDLE_VALUE) {
        LogToFile("CheckThreadIntegrity: Invalid thread handle.");
        return false;
    }

    NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInformationThread) {
        LogToFile("CheckThreadIntegrity: NtQueryInformationThread not found.");
        return false;
    }

    THREAD_BASIC_INFORMATION tbi = { 0 };
    NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
    if (!NT_SUCCESS(status)) {
        LogToFile("CheckThreadIntegrity: NtQueryInformationThread failed, status: " + std::to_string(status));
        return false;
    }

    PVOID startAddress = NULL;
    status = NtQueryInformationThread(hThread, 9, &startAddress, sizeof(startAddress), NULL);
    if (NT_SUCCESS(status) && startAddress) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (VirtualQuery(startAddress, &mbi, sizeof(mbi))) {
            if (mbi.AllocationBase != GetModuleHandle(NULL)) {
                LogToFile("CheckThreadIntegrity: Suspicious start address for thread.");
                return false;
            }
        }
    }

    LogToFile("CheckThreadIntegrity: Thread integrity verified.");
    return true;
}

void HideThread(HANDLE hThread) {
    if (!hThread || hThread == INVALID_HANDLE_VALUE) {
        LogToFile("HideThread: Invalid thread handle.");
        return;
    }

    NtSetInformationThread_t NtSetInformationThread = (NtSetInformationThread_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    if (!NtSetInformationThread) {
        LogToFile("HideThread: NtSetInformationThread not found.");
        return;
    }

    NTSTATUS status = NtSetInformationThread(hThread, 0x11, NULL, 0); // ThreadHideFromDebugger
    if (NT_SUCCESS(status)) {
        LogToFile("HideThread: Thread hidden from debugger.");
    }
    else {
        LogToFile("HideThread: NtSetInformationThread failed, status: " + std::to_string(status));
    }
}

bool IsDebuggerPresentCustom() {
    bool result = IsDebuggerPresent() || CheckIsDebuggerPresentDirect() || CheckDebugObject() || CheckRemoteDebugger() || CheckDebugPort();
    LogToFile("IsDebuggerPresentCustom: Result = " + std::to_string(result));
    return result;
}

bool CheckForHardwareBreakpoints() {
    return CheckHardwareBreakpointsAdvanced();
}

bool CheckForSoftwareBreakpoints() {
    return CheckSoftwareBreakpointsAdvanced();
}

bool CheckForTimingAttacks() {
    return CheckTimingAdvanced();
}

std::string GetCurrentProcessName() {
    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        LogToFile("GetCurrentProcessName: GetModuleFileNameW failed, error: " + std::to_string(GetLastError()));
        return "";
    }

    std::wstring exeName = PathFindFileNameW(exePath);
    return WStringToString(exeName);
}

bool IsRandomizedName(const std::string& name) {
    if (name.empty()) return false;
    bool hasLetters = false, hasNumbers = false;
    for (char c : name) {
        if (std::isalpha(c)) hasLetters = true;
        if (std::isdigit(c)) hasNumbers = true;
    }
    bool result = hasLetters && hasNumbers && name.length() > 8;
    LogToFile("IsRandomizedName: Name = " + name + ", Result = " + std::to_string(result));
    return result;
}

std::string GenerateRandomExeName() {
    std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

    std::string randomName;
    for (int i = 0; i < 12; i++) {
        randomName += chars[dis(gen)];
    }
    randomName += ".exe";
    LogToFile("GenerateRandomExeName: Generated name = " + randomName);
    return randomName;
}

std::string GenerateRandomBatName() {
    std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

    std::string randomName;
    for (int i = 0; i < 12; i++) {
        randomName += chars[dis(gen)];
    }
    randomName += ".bat";
    LogToFile("GenerateRandomBatName: Generated name = " + randomName);
    return randomName;
}

void RandomizeProcessName() {
    std::string newName = GenerateRandomExeName();
    std::wstring wNewName = StringToWString(newName);

    if (!MoveFileW(StringToWString(GetCurrentProcessName()).c_str(), wNewName.c_str())) {
        LogToFile("RandomizeProcessName: MoveFileW failed, error: " + std::to_string(GetLastError()));
        return;
    }
    LogToFile("RandomizeProcessName: Process name randomized to " + newName);
}

bool CheckForSuspiciousFilesInDirectory() {
    std::vector<std::wstring> suspiciousExtensions = { L".dmp", L".log", L".trace" };
    wchar_t currentDir[MAX_PATH] = { 0 };
    if (!GetCurrentDirectoryW(MAX_PATH, currentDir)) {
        LogToFile("CheckForSuspiciousFilesInDirectory: GetCurrentDirectoryW failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    std::wstring searchPath = std::wstring(currentDir) + L"\\*.*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        LogToFile("CheckForSuspiciousFilesInDirectory: FindFirstFileW failed, error: " + std::to_string(GetLastError()));
        return false;
    }

    bool foundSuspicious = false;
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring fileName = findData.cFileName;
            std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::towlower);
            for (const auto& ext : suspiciousExtensions) {
                if (fileName.find(ext) != std::wstring::npos) {
                    LogToFile("CheckForSuspiciousFilesInDirectory: Suspicious file found: " + WStringToString(fileName));
                    foundSuspicious = true;
                    break;
                }
            }
        }
    } while (!foundSuspicious && FindNextFileW(hFind, &findData));

    FindClose(hFind);
    if (!foundSuspicious) {
        LogToFile("CheckForSuspiciousFilesInDirectory: No suspicious files found.");
    }
    return foundSuspicious;
}

void ClearActivityTraces() {
    std::vector<std::wstring> traceFiles = { L"debug_log.txt", L"*.dmp", L"*.trace" };
    wchar_t currentDir[MAX_PATH] = { 0 };
    if (!GetCurrentDirectoryW(MAX_PATH, currentDir)) {
        LogToFile("ClearActivityTraces: GetCurrentDirectoryW failed, error: " + std::to_string(GetLastError()));
        return;
    }

    for (const auto& pattern : traceFiles) {
        std::wstring searchPath = std::wstring(currentDir) + L"\\" + pattern;
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring filePath = std::wstring(currentDir) + L"\\" + findData.cFileName;
                    if (DeleteFileW(filePath.c_str())) {
                        LogToFile("ClearActivityTraces: Deleted trace file: " + WStringToString(filePath));
                    }
                    else {
                        LogToFile("ClearActivityTraces: Failed to delete trace file: " + WStringToString(filePath) + ", error: " + std::to_string(GetLastError()));
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    LogToFile("ClearActivityTraces: Activity traces cleared.");
}

bool CheckSessionWithServer(const std::string& sessionid) {
    // Функция-заглушка, так как сетевые вызовы не требуются
    LogToFile("CheckSessionWithServer: Session check for ID " + sessionid + " not implemented (network calls disabled).");
    return false;
}

void InitializeAntiInject(const std::string& key) {
    HANDLE hThread = CreateThread(NULL, 0, AntiInjectThread, (LPVOID)key.c_str(), 0, NULL);
    if (hThread) {
        LogToFile("InitializeAntiInject: Anti-inject thread started with key: " + key);
        CloseHandle(hThread);
    }
    else {
        LogToFile("InitializeAntiInject: CreateThread failed, error: " + std::to_string(GetLastError()));
    }
}

void InitializeAntiDebug() {
    HANDLE hThread = CreateThread(NULL, 0, DebuggerCheckThread, NULL, 0, NULL);
    if (hThread) {
        LogToFile("InitializeAntiDebug: Debugger check thread started.");
        CloseHandle(hThread);
    }
    else {
        LogToFile("InitializeAntiDebug: CreateThread failed, error: " + std::to_string(GetLastError()));
    }
}

void CleanupAntiDebug() {
    debuggerDetected.store(false);
    LogToFile("CleanupAntiDebug: Debugger detection state reset.");
}

void InitializeDllLoadMonitoring() {
    LdrRegisterDllNotification_t LdrRegisterDllNotification = (LdrRegisterDllNotification_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification");
    if (!LdrRegisterDllNotification) {
        LogToFile("InitializeDllLoadMonitoring: LdrRegisterDllNotification not found.");
        return;
    }

    auto DllNotificationCallback = [](ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context) {
        if (NotificationReason == 1) { // LDR_DLL_NOTIFICATION_REASON_LOADED
            std::wstring dllName = NotificationData->BaseDllName->Buffer;
            LogToFile("DllLoadMonitoring: DLL loaded: " + WStringToString(dllName));
            if (CheckForInjectedModules()) {
                debuggerDetected.store(true);
                ShowMessageAndExit();
            }
        }
        };

    NTSTATUS status = LdrRegisterDllNotification(0, DllNotificationCallback, NULL, &dllNotificationCookie);
    if (NT_SUCCESS(status)) {
        LogToFile("InitializeDllLoadMonitoring: DLL load monitoring initialized.");
    }
    else {
        LogToFile("InitializeDllLoadMonitoring: LdrRegisterDllNotification failed, status: " + std::to_string(status));
    }
}

void CleanupDllLoadMonitoring() {
    if (dllNotificationCookie) {
        LdrUnregisterDllNotification_t LdrUnregisterDllNotification = (LdrUnregisterDllNotification_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrUnregisterDllNotification");
        if (LdrUnregisterDllNotification) {
            NTSTATUS status = LdrUnregisterDllNotification(dllNotificationCookie);
            if (NT_SUCCESS(status)) {
                LogToFile("CleanupDllLoadMonitoring: DLL load monitoring cleaned up.");
            }
            else {
                LogToFile("CleanupDllLoadMonitoring: LdrUnregisterDllNotification failed, status: " + std::to_string(status));
            }
        }
        dllNotificationCookie = NULL;
    }
}

DWORD WINAPI AntiInjectThread(LPVOID lpParam) {
    std::string key = lpParam ? std::string((const char*)lpParam) : "";
    LogToFile("AntiInjectThread: Started with key: " + key);
    while (true) {
        if (CheckForInjectedModules() || CheckForHookInjection() || CheckForAPCInjection() || CheckForRemoteThreadInjection()) {
            debuggerDetected.store(true);
            ShowMessageAndExit();
        }
        Sleep(5000);
    }
    return 0;
}

DWORD WINAPI CheckSuspiciousFilesThread(LPVOID lpParam) {
    LogToFile("CheckSuspiciousFilesThread: Started.");
    while (true) {
        if (CheckForSuspiciousFilesInDirectory()) {
            debuggerDetected.store(true);
            ShowMessageAndExit();
        }
        Sleep(10000);
    }
    return 0;
}

DWORD WINAPI DebuggerCheckThread(LPVOID lpParam) {
    LogToFile("DebuggerCheckThread: Started.");
    while (true) {
        if (PerformAntiDebugChecks()) {
            debuggerDetected.store(true);
            ShowMessageAndExit();
        }
        Sleep(5000);
    }
    return 0;
}

DWORD WINAPI MemoryIntegrityThread(LPVOID lpParam) {
    LogToFile("MemoryIntegrityThread: Started.");
    while (true) {
        if (!CheckMemoryIntegrity()) {
            debuggerDetected.store(true);
            ShowMessageAndExit();
        }
        Sleep(10000);
    }
    return 0;
}

void PeriodicAntiDebugCheck(const std::string& key) {
    LogToFile("PeriodicAntiDebugCheck: Started with key: " + key);
    if (PerformAntiDebugChecks()) {
        debuggerDetected.store(true);
        ShowMessageAndExit();
    }
}

bool PerformAntiDebugChecks() {
    std::lock_guard<std::mutex> lock(debuggerMutex);
    bool detected = (IsDebuggerPresentCustom() ||
        CheckNtGlobalFlag() ||
        CheckHeapFlags() ||
        CheckProcessDebugFlags() ||
        CheckParentProcess() ||
        CheckOutputDebugStringAdvanced() ||
        CheckSoftwareBreakpointsAdvanced() ||
        CheckHardwareBreakpointsAdvanced() ||
        CheckAssemblyInstructions() ||
        CheckExceptions() ||
        CheckTimingAdvanced() ||
        CheckForDebuggerProcesses() ||
        CheckForDebuggerStrings() ||
        CheckForActiveDebuggerWindows() ||
        CheckForDebuggerDrivers() ||
        CheckForFunctionHooks() ||
        CheckForInjectedModules() ||
        CheckForVirtualProtectAbuse() ||
        CheckForExplorerDebuggerFolder() ||
        CheckGlobalFlagsClearInProcess() ||
        CheckGlobalFlagsClearInFile() ||
        CheckForDebuggerRegistryKeys() ||
        CheckForIFEODebugger() ||
        CheckNoDebugInherit() ||
        CheckExceptionCount() ||
        CheckForAnalysisToolsViaWMI() ||
        CheckForSystemCallHooks() ||
        CheckForThreadHiding() ||
        CheckForModuleHiding() ||
        CheckForMemoryPatches() ||
        CheckForDriverSignatureEnforcement() ||
        CheckForTestSigningMode() ||
        CheckForUnsignedDrivers() ||
        CheckForDriverHiding() ||
        CheckForDriverHooks() ||
        CheckForDriverInjection() ||
        CheckForAPCInjection() ||
        CheckForHookInjection() ||
        CheckForRemoteThreadInjection());

    if (detected) {
        LogToFile("PerformAntiDebugChecks: Debugger detected.");
    }
    else {
        LogToFile("PerformAntiDebugChecks: No debugger detected.");
    }
    return detected;
}