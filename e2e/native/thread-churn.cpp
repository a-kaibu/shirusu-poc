#include <windows.h>

static DWORD expected_pid;
static DWORD WINAPI worker(void*) {
    for (unsigned i = 0; i < 32; ++i) {
        SetLastError(0x1234abcd);
        if (GetCurrentProcessId() != expected_pid || GetLastError() != 0x1234abcd) return 20;
    }
    return 0;
}
static bool marker(const wchar_t* name) {
    HANDLE file = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    return file != INVALID_HANDLE_VALUE && CloseHandle(file) != FALSE;
}
extern "C" void __cdecl entry() {
    expected_pid = GetCurrentProcessId();
    if (!marker(L"ready")) ExitProcess(10);
    const ULONGLONG deadline = GetTickCount64() + 90000;
    while (GetFileAttributesW(L"stop") == INVALID_FILE_ATTRIBUTES) {
        HANDLE threads[16];
        for (unsigned i = 0; i < 16; ++i) {
            threads[i] = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
            if (!threads[i]) ExitProcess(11);
        }
        for (unsigned i = 0; i < 16; ++i) {
            DWORD result = 99;
            if (WaitForSingleObject(threads[i], INFINITE) != WAIT_OBJECT_0 ||
                !GetExitCodeThread(threads[i], &result) || result != 0 ||
                !CloseHandle(threads[i])) ExitProcess(12);
        }
        if (GetTickCount64() >= deadline) ExitProcess(13);
    }
    ExitProcess(0);
}
