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

// Simulate an application/third-party IAT wrapper installed before capture.
static DWORD (WINAPI *original_pid)();
static volatile LONG wrapper_calls;
static DWORD WINAPI wrapped_pid() {
    InterlockedIncrement(&wrapper_calls);
    return original_pid();
}
static bool same_name(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static bool wrap_pid_import() {
    auto base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; imports->Name; ++imports) {
        if (!imports->OriginalFirstThunk) continue;
        auto names = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports->OriginalFirstThunk);
        auto slots = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports->FirstThunk);
        for (; names->u1.AddressOfData; ++names, ++slots) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
            auto name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
            if (!same_name(reinterpret_cast<const char*>(name->Name), "GetCurrentProcessId")) continue;
            original_pid = reinterpret_cast<DWORD (WINAPI*)()>(slots->u1.Function);
            DWORD old = 0;
            if (!VirtualProtect(&slots->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) return false;
            InterlockedExchangePointer(reinterpret_cast<void* volatile*>(&slots->u1.Function),
                                       reinterpret_cast<void*>(&wrapped_pid));
            DWORD ignored = 0;
            return VirtualProtect(&slots->u1.Function, sizeof(void*), old, &ignored) != FALSE;
        }
    }
    return false;
}

extern "C" void __cdecl entry() {
    if (!wrap_pid_import()) ExitProcess(19);
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
            const LONG before = wrapper_calls;
            for (unsigned i = 0; i < 100; ++i) {
                SetLastError(0x1234abcd);
                if (GetCurrentProcessId() != pid || GetLastError() != 0x1234abcd) ExitProcess(17);
            }
            if (wrapper_calls - before != 100) ExitProcess(20);
            exercised = true;
            if (!marker(L"exercise-done")) ExitProcess(18);
        }
        if (GetTickCount64() >= deadline) ExitProcess(15);
        Sleep(5);
    }
    if (!checked || !exercised) ExitProcess(16);
    ExitProcess(0);
}
