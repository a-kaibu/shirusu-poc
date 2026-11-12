// Native SEH must propagate through HeapAlloc's detour to the original caller.
#include <windows.h>
#include <stdio.h>
__declspec(noinline) DWORD exercise() {
    __try {
        void* p = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, (SIZE_T)-1);
        if (p) HeapFree(GetProcessHeap(), 0, p);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    DWORD code = exercise();
    if (code != STATUS_NO_MEMORY) return 3;
    FILE* f = NULL;
    if (fopen_s(&f, argv[1], "wb") || !f) return 4;
    fprintf(f, "caught=%08lx\n", code);
    fclose(f);
    return 0;
}
