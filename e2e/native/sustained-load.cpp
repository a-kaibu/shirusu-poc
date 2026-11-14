// Sustained high-frequency load (review P1): the same three public calls as
// the high-load benchmark (GetCurrentProcessId + HeapAlloc + HeapFree), kept
// up for a fixed duration instead of a finite burst. A finite burst lets the
// Host keep converting after the application exits; a sustained run shows
// whether collection, conversion and the queue keep up over time.
//
// Usage: sustained-load <seconds> <iterations-per-second | max>
// Writes measurement.json with the total and per-second iteration counts.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned kMaxSeconds = 120;
static const unsigned kBatch = 64;

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    const unsigned seconds = (unsigned)strtoul(argv[1], nullptr, 10);
    if (seconds == 0 || seconds > kMaxSeconds) return 2;
    const bool unpaced = strcmp(argv[2], "max") == 0;
    const unsigned long long rate = unpaced ? 0 : strtoull(argv[2], nullptr, 10);
    if (!unpaced && rate == 0) return 2;
    LARGE_INTEGER frequency, start, now;
    if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&start)) return 3;
    const long long f = frequency.QuadPart;
    const long long end_tick = start.QuadPart + (long long)seconds * f;
    HANDLE heap = GetProcessHeap();
    unsigned long long per_second[kMaxSeconds] = {};
    unsigned long long total = 0;
    unsigned checksum = 0;
    for (;;) {
        if (!QueryPerformanceCounter(&now)) return 4;
        if (now.QuadPart >= end_tick) break;
        const long long elapsed = now.QuadPart - start.QuadPart;
        if (!unpaced) {
            // Pace in batches: run only while behind the target schedule.
            const unsigned long long due =
                (unsigned long long)((double)elapsed * (double)rate / (double)f);
            if (total >= due) {
                YieldProcessor();
                continue;
            }
        }
        for (unsigned i = 0; i < kBatch; ++i) {
            if (GetCurrentProcessId() == 0) return 5;
            auto* block = (volatile unsigned*)HeapAlloc(heap, 0, 64);
            if (!block) return 6;
            *block = (unsigned)total + i;
            checksum ^= *block;
            if (!HeapFree(heap, 0, (void*)block)) return 7;
        }
        total += kBatch;
        const unsigned bucket = (unsigned)(elapsed / f);
        if (bucket < seconds) per_second[bucket] += kBatch;
    }
    FILE* output = nullptr;
    if (fopen_s(&output, "measurement.json", "w") != 0) return 8;
    fprintf(output, "{\"seconds\":%u,\"rate\":%llu,\"iterations\":%llu,\"ticks\":%lld,"
                    "\"qpc_frequency\":%lld,\"checksum\":%u,\"per_second\":[",
            seconds, rate, total, now.QuadPart - start.QuadPart, f, checksum);
    for (unsigned s = 0; s < seconds; ++s) {
        fprintf(output, s ? ",%llu" : "%llu", per_second[s]);
    }
    fprintf(output, "]}\n");
    if (fclose(output) != 0) return 9;
    return 0;
}
