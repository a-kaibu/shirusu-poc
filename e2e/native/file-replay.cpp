// A CRT-free application makes exactly the six file calls under test.
// Build twice with /DTEST_BYTE=42 and /DTEST_BYTE=43 for a known data difference.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef TEST_BYTE
#define TEST_BYTE 42
#endif
extern "C" void WINAPI entry() {
    const wchar_t* path = L"captured-file.bin";
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) ExitProcess(10);
    char byte = TEST_BYTE;
    DWORD count = 0;
    if (!WriteFile(file, &byte, 1, &count, nullptr) || count != 1) ExitProcess(11);
    if (!CloseHandle(file)) ExitProcess(12);
    file = CreateFileW(path, GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) ExitProcess(13);
    byte = 0;
    if (!ReadFile(file, &byte, 1, &count, nullptr) || count != 1 || byte != TEST_BYTE)
        ExitProcess(14);
    if (!CloseHandle(file)) ExitProcess(15);
    ExitProcess(0);
}
