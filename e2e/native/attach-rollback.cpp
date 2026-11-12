#include <windows.h>

static bool exists(const wchar_t* name) {
    return GetFileAttributesW(name) != INVALID_FILE_ATTRIBUTES;
}
static bool marker(const wchar_t* name) {
    HANDLE file = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    return CloseHandle(file) != FALSE;
}

extern "C" void __cdecl entry() {
    const DWORD pid = GetCurrentProcessId();
    auto address = reinterpret_cast<const volatile unsigned char*>(
        GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "GetCurrentProcessId"));
    if (!address) ExitProcess(10);
    unsigned char original[16];
    for (unsigned i = 0; i < sizeof(original); ++i) original[i] = address[i];
    if (!marker(L"ready")) ExitProcess(11);
    const ULONGLONG deadline = GetTickCount64() + 90000;
    bool checked = false;
    bool exercised = false;
    while (!exists(L"stop")) {
        SetLastError(0x1234abcd);
        if (GetCurrentProcessId() != pid || GetLastError() != 0x1234abcd) ExitProcess(12);
        if (!checked && exists(L"check-rollback")) {
            for (unsigned i = 0; i < sizeof(original); ++i) {
                if (original[i] != address[i]) ExitProcess(13);
            }
            checked = true;
            if (!marker(L"rollback-checked")) ExitProcess(14);
        }
        if (!exercised && exists(L"exercise")) {
            for (unsigned i = 0; i < 100; ++i) {
                SetLastError(0x1234abcd);
                if (GetCurrentProcessId() != pid || GetLastError() != 0x1234abcd) ExitProcess(17);
            }
            exercised = true;
            if (!marker(L"exercise-done")) ExitProcess(18);
        }
        if (GetTickCount64() >= deadline) ExitProcess(15);
        Sleep(5);
    }
    if (!checked || !exercised) ExitProcess(16);
    ExitProcess(0);
}
