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
