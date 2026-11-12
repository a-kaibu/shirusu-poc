// CRT-free native coverage for ANSI / file-discovery APIs. Each run operates in
// its own working directory and a process-specific volatile HKCU test key.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static void require(bool ok, UINT code) { if (!ok) ExitProcess(code); }
extern "C" void __cdecl entry() {
    char path[1024]; wchar_t wide[1024];
    require(GetTempPathA(1024, path) != 0, 10);
    require(GetCurrentDirectoryA(1024, path) != 0, 11);
    require(SetCurrentDirectoryA(".") != 0, 12);
    require(CreateDirectoryA("files", nullptr) != 0, 13);
    HANDLE f = CreateFileA("files\\one.bin", GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    require(f != INVALID_HANDLE_VALUE, 14);
    DWORD size = 0; const DWORD data = 0x1234abcd;
    require(WriteFile(f, &data, sizeof(data), &size, nullptr) && size == sizeof(data), 15);
    BY_HANDLE_FILE_INFORMATION info;
    require(GetFileInformationByHandle(f, &info) && info.nFileSizeLow == sizeof(data), 16);
    FILE_STANDARD_INFO standard;
    require(GetFileInformationByHandleEx(f, FileStandardInfo, &standard, sizeof(standard)) &&
            standard.EndOfFile.QuadPart == sizeof(data), 17);
    FILE_BASIC_INFO basic = {};
    basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    require(SetFileInformationByHandle(f, FileBasicInfo, &basic, sizeof(basic)) != 0, 18);
    require(CloseHandle(f) != 0, 19);
    require(CopyFileA("files\\one.bin", "files\\two.bin", TRUE) != 0, 20);
    require(MoveFileA("files\\two.bin", "files\\three.bin") != 0, 21);
    require(GetFileAttributesA("files\\three.bin") != INVALID_FILE_ATTRIBUTES, 22);
    require(SetFileAttributesA("files\\three.bin", FILE_ATTRIBUTE_NORMAL) != 0, 23);
    WIN32_FIND_DATAA found; WIN32_FIND_DATAW found_w;
    HANDLE a = FindFirstFileA("files\\*.bin", &found);
    require(a != INVALID_HANDLE_VALUE && FindNextFileA(a, &found), 24);
    require(FindClose(a) != 0, 25);
    HANDLE w = FindFirstFileW(L"files\\*.bin", &found_w);
    require(w != INVALID_HANDLE_VALUE && FindNextFileW(w, &found_w), 26);
    require(FindClose(w) != 0, 27);
    require(GetFullPathNameA("files\\one.bin", 1024, path, nullptr) != 0, 28);
    require(GetFullPathNameW(L"files\\one.bin", 1024, wide, nullptr) != 0, 29);
    require(GetLongPathNameA("files\\one.bin", path, 1024) != 0, 30);
    require(GetLongPathNameW(L"files\\one.bin", wide, 1024) != 0, 31);
    require(GetShortPathNameA("files\\one.bin", path, 1024) != 0, 32);
    require(GetShortPathNameW(L"files\\one.bin", wide, 1024) != 0, 33);
    ULARGE_INTEGER available, total, free_bytes;
    require(GetDiskFreeSpaceExA(nullptr, &available, &total, &free_bytes) && total.QuadPart, 34);
    require(GetDiskFreeSpaceExW(nullptr, &available, &total, &free_bytes) && total.QuadPart, 35);
    require(GetDriveTypeA(nullptr) > DRIVE_NO_ROOT_DIR, 36);
    require(GetDriveTypeW(nullptr) > DRIVE_NO_ROOT_DIR, 37);
    require(GetLogicalDrives() != 0, 38);
    require(GetLogicalDriveStringsA(1024, path) != 0, 39);
    require(GetLogicalDriveStringsW(1024, wide) != 0, 40);
    require(DeleteFileA("files\\one.bin") && DeleteFileA("files\\three.bin"), 41);
    require(RemoveDirectoryA("files") != 0, 42);
    SetLastError(0);
    require(GetFileAttributesA("missing.bin") == INVALID_FILE_ATTRIBUTES &&
            GetLastError() == ERROR_FILE_NOT_FOUND, 43);

    char key_name[] = "Software\\shirusu-ci-00000000";
    DWORD pid = GetCurrentProcessId();
    for (unsigned i = 0; i < 8; ++i) {
        key_name[sizeof(key_name) - 2 - i] = "0123456789abcdef"[pid & 15];
        pid >>= 4;
    }
    HKEY key = nullptr, child = nullptr, opened = nullptr;
    DWORD disposition = 0;
    require(RegCreateKeyExA(HKEY_CURRENT_USER, key_name, 0, nullptr, REG_OPTION_VOLATILE,
                           KEY_ALL_ACCESS, nullptr, &key, &disposition) == ERROR_SUCCESS &&
            disposition == REG_CREATED_NEW_KEY, 50);
    require(RegCreateKeyExA(key, "child", 0, nullptr, REG_OPTION_VOLATILE,
                           KEY_ALL_ACCESS, nullptr, &child, nullptr) == ERROR_SUCCESS, 51);
    require(RegCloseKey(child) == ERROR_SUCCESS, 52);
    require(RegOpenKeyExA(key, "child", 0, KEY_READ, &opened) == ERROR_SUCCESS, 53);
    require(RegCloseKey(opened) == ERROR_SUCCESS, 54);
    require(RegSetValueExA(key, "value", 0, REG_DWORD, (const BYTE*)&data, sizeof(data)) == ERROR_SUCCESS, 55);
    DWORD got = 0, type = 0; size = sizeof(got);
    require(RegQueryValueExA(key, "value", nullptr, &type, (BYTE*)&got, &size) == ERROR_SUCCESS &&
            got == data && type == REG_DWORD && size == sizeof(got), 56);
    DWORD length = 1024;
    require(RegEnumKeyExA(key, 0, path, &length, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS, 57);
    length = 1024; size = sizeof(got);
    require(RegEnumValueA(key, 0, path, &length, nullptr, &type, (BYTE*)&got, &size) == ERROR_SUCCESS, 58);
    DWORD subkeys = 0, values = 0;
    require(RegQueryInfoKeyA(key, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
                            &values, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS &&
            subkeys == 1 && values == 1, 59);
    require(RegDeleteValueA(key, "value") == ERROR_SUCCESS, 60);
    require(RegDeleteKeyA(key, "child") == ERROR_SUCCESS, 61);
    require(RegCloseKey(key) == ERROR_SUCCESS, 62);
    require(RegDeleteKeyA(HKEY_CURRENT_USER, key_name) == ERROR_SUCCESS, 63);
    f = CreateFileA("result.bin", GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    require(f != INVALID_HANDLE_VALUE, 64);
    require(WriteFile(f, &data, sizeof(data), &size, nullptr) && size == sizeof(data), 65);
    require(CloseHandle(f) != 0, 66);
    ExitProcess(0);
}
