// Review P0: threads terminated by TerminateThread while recording.
//
// Spinner threads call a captured API in a tight loop, so most of their time
// is spent inside the recorder (Detour, Ring writer). The main thread
// terminates them at arbitrary points, then starts short-lived threads that
// must still be captured. TerminateThread runs no destructor and no exit
// notification, so a spinner cut off inside the writer leaves its ownership
// flag set. Before the fix, a later thread that reused the terminated
// thread's ID waited for that flag forever. Spinners are terminated only
// after warm-up, so they never hold the heap or Agent registration locks.
#include <windows.h>
#include <dbghelp.h>

// Crash report (diagnostics only): an unhandled exception writes its code,
// address and symbolized stack to crash.txt, which the CI script prints.
static HANDLE crash_file = INVALID_HANDLE_VALUE;
static void put(const char* text) {
    DWORD written = 0;
    DWORD length = 0;
    while (text[length]) ++length;
    WriteFile(crash_file, text, length, &written, nullptr);
}
static void put_hex(ULONG64 value) {
    char buffer[19] = "0x";
    for (int i = 0; i < 16; ++i) {
        const unsigned digit = (unsigned)(value >> (60 - 4 * i)) & 0xf;
        buffer[2 + i] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
    }
    buffer[18] = 0;
    put(buffer);
}
static LONG WINAPI crash_filter(EXCEPTION_POINTERS* info) {
    crash_file = CreateFileW(L"crash.txt", GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (crash_file == INVALID_HANDLE_VALUE) return EXCEPTION_CONTINUE_SEARCH;
    put("code ");
    put_hex(info->ExceptionRecord->ExceptionCode);
    put(" address ");
    put_hex((ULONG64)info->ExceptionRecord->ExceptionAddress);
    if (info->ExceptionRecord->NumberParameters >= 2) {
        put(" access ");
        put_hex(info->ExceptionRecord->ExceptionInformation[0]);
        put(" at ");
        put_hex(info->ExceptionRecord->ExceptionInformation[1]);
    }
    put(" thread ");
    put_hex(GetCurrentThreadId());
    put("\r\n");
    HANDLE process = GetCurrentProcess();
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
    const BOOL symbols = SymInitialize(process, nullptr, TRUE);
    void* frames[62];
    const USHORT count = RtlCaptureStackBackTrace(0, 62, frames, nullptr);
    alignas(SYMBOL_INFO) char storage[sizeof(SYMBOL_INFO) + 512];
    for (USHORT i = 0; i < count; ++i) {
        const DWORD64 address = (DWORD64)frames[i];
        put_hex(address);
        HMODULE module = nullptr;
        char path[MAX_PATH];
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)frames[i], &module) &&
            GetModuleFileNameA(module, path, MAX_PATH)) {
            const char* name = path;
            for (const char* c = path; *c; ++c) if (*c == '\\') name = c + 1;
            put(" ");
            put(name);
            put("+");
            put_hex(address - (DWORD64)module);
        }
        SYMBOL_INFO* symbol = (SYMBOL_INFO*)storage;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 511;
        DWORD64 displacement = 0;
        if (symbols && SymFromAddr(process, address, &displacement, symbol)) {
            put(" ");
            put(symbol->Name);
        }
        put("\r\n");
    }
    CloseHandle(crash_file);
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD expected_pid;
static volatile LONG warmed;

static DWORD WINAPI spinner(void*) {
    for (unsigned i = 0; i < 64; ++i) {
        if (GetCurrentProcessId() != expected_pid) return 20;
    }
    InterlockedIncrement(&warmed);
    for (;;) {
        if (GetCurrentProcessId() != expected_pid) return 21;
    }
}
static DWORD WINAPI finite(void*) {
    for (unsigned i = 0; i < 32; ++i) {
        if (GetCurrentProcessId() != expected_pid) return 20;
    }
    return 0;
}
static bool marker(const wchar_t* name) {
    HANDLE file = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    return file != INVALID_HANDLE_VALUE && CloseHandle(file) != FALSE;
}
static bool exists(const wchar_t* name) {
    return GetFileAttributesW(name) != INVALID_FILE_ATTRIBUTES;
}
static const unsigned kRounds = 48;
static const unsigned kSpinners = 4;
static const unsigned kFinite = 8;

extern "C" void __cdecl entry() {
    SetUnhandledExceptionFilter(crash_filter);
    expected_pid = GetCurrentProcessId();
    if (!marker(L"ready")) ExitProcess(10);
    const ULONGLONG deadline = GetTickCount64() + 120000;
    while (!exists(L"go")) {
        if (GetTickCount64() >= deadline) ExitProcess(11);
        Sleep(5);
    }
    for (unsigned round = 0; round < kRounds; ++round) {
        HANDLE spinners[kSpinners];
        InterlockedExchange(&warmed, 0);
        for (unsigned i = 0; i < kSpinners; ++i) {
            spinners[i] = CreateThread(nullptr, 0, spinner, nullptr, 0, nullptr);
            if (!spinners[i]) ExitProcess(12);
        }
        while (InterlockedCompareExchange(&warmed, 0, 0) != (LONG)kSpinners) {
            if (GetTickCount64() >= deadline) ExitProcess(13);
            Sleep(0);
        }
        Sleep(round % 3);
        for (unsigned i = 0; i < kSpinners; ++i) {
            if (!TerminateThread(spinners[i], 0xdead)) ExitProcess(14);
        }
        for (unsigned i = 0; i < kSpinners; ++i) {
            if (WaitForSingleObject(spinners[i], INFINITE) != WAIT_OBJECT_0 ||
                !CloseHandle(spinners[i])) ExitProcess(15);
        }
        // New threads (often reusing terminated thread IDs) must still run
        // and be captured.
        HANDLE threads[kFinite];
        for (unsigned i = 0; i < kFinite; ++i) {
            threads[i] = CreateThread(nullptr, 0, finite, nullptr, 0, nullptr);
            if (!threads[i]) ExitProcess(16);
        }
        for (unsigned i = 0; i < kFinite; ++i) {
            DWORD result = 99;
            if (WaitForSingleObject(threads[i], INFINITE) != WAIT_OBJECT_0 ||
                !GetExitCodeThread(threads[i], &result) || result != 0 ||
                !CloseHandle(threads[i])) ExitProcess(17);
        }
        if (GetTickCount64() >= deadline) ExitProcess(18);
    }
    if (!marker(L"done")) ExitProcess(19);
    while (!exists(L"stop")) {
        if (GetTickCount64() >= deadline) ExitProcess(20);
        Sleep(5);
    }
    ExitProcess(0);
}
