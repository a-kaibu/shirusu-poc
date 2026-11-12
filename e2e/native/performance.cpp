// Measure real application work inside the process, excluding DLL injection and
// Host startup. No synthetic API body, spin calibration, or timed file output.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned paints = 0;
static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w, LPARAM l) {
    if (message == WM_PAINT) {
        PAINTSTRUCT paint;
        HDC dc = BeginPaint(window, &paint);
        if (!dc) return 0;
        for (int row = 0; row < 20; ++row) {
            RECT rect = {10, row * 12, 300, row * 12 + 10};
            FillRect(dc, &rect, (HBRUSH)GetStockObject(LTGRAY_BRUSH));
            TextOutW(dc, 14, row * 12, L"shirusu native GUI workload", 26);
        }
        EndPaint(window, &paint);
        ++paints;
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const bool gui = strcmp(argv[1], "gui") == 0;
    if (!gui && strcmp(argv[1], "high-load") != 0) return 2;
    const unsigned iterations = gui ? 300 : 50000;
    LARGE_INTEGER frequency, start, end;
    if (!QueryPerformanceFrequency(&frequency)) return 3;
    HWND window = nullptr;
    HANDLE heap = GetProcessHeap();
    if (gui) {
        WNDCLASSEXW cls = {};
        cls.cbSize = sizeof(cls);
        cls.hInstance = GetModuleHandleW(nullptr);
        cls.lpfnWndProc = window_proc;
        cls.lpszClassName = L"ShirusuNativePerformance";
        if (!RegisterClassExW(&cls)) return 4;
        window = CreateWindowExW(0, cls.lpszClassName, L"shirusu performance",
                                 WS_OVERLAPPEDWINDOW, 0, 0, 360, 320,
                                 nullptr, nullptr, cls.hInstance, nullptr);
        if (!window) return 5;
        ShowWindow(window, SW_SHOWNOACTIVATE);
        UpdateWindow(window);
    }
    // The checksum and paint count ensure actual work occurred in both modes.
    unsigned checksum = 0;
    const unsigned before_paints = paints;
    if (!QueryPerformanceCounter(&start)) return 6;
    for (unsigned i = 0; i < iterations; ++i) {
        if (gui) {
            if (!InvalidateRect(window, nullptr, FALSE) || !UpdateWindow(window)) return 7;
            MSG message;
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        } else {
            // Three real, high-frequency public Windows calls per iteration.
            if (GetCurrentProcessId() == 0) return 8;
            auto* block = (volatile unsigned*)HeapAlloc(heap, 0, 64);
            if (!block) return 9;
            *block = i;
            checksum ^= *block;
            if (!HeapFree(heap, 0, (void*)block)) return 10;
        }
    }
    if (!QueryPerformanceCounter(&end) || end.QuadPart <= start.QuadPart) return 11;
    if (gui && paints - before_paints != iterations) return 12;
    if (window && !DestroyWindow(window)) return 13;
    FILE* output = nullptr;
    if (fopen_s(&output, "measurement.json", "w") != 0) return 14;
    fprintf(output, "{\"workload\":\"%s\",\"iterations\":%u,\"ticks\":%lld,"
                    "\"qpc_frequency\":%lld,\"paint_count\":%u,\"checksum\":%u}\n",
            argv[1], iterations, end.QuadPart - start.QuadPart, frequency.QuadPart,
            paints - before_paints, checksum);
    if (fclose(output) != 0) return 15;
    return 0;
}
