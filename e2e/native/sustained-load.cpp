// Sustained high-frequency load (review P1): the same three public calls as
// the high-load benchmark (GetCurrentProcessId + HeapAlloc + HeapFree), kept
// up for a fixed duration instead of a finite burst. A finite burst lets the
// Host keep converting after the application exits; a sustained run shows
// whether collection, conversion and the queue keep up over time.
//
// Usage: sustained-load <seconds> <iterations-per-second | max> [threads]
// Writes measurement.json with the total and per-second iteration counts and
// the number of Sleep calls made while pacing.
//
// The loop must not call any other Windows API: QueryPerformanceCounter is
// captured too, and calling it per pacing check produced tens of millions of
// extra events. Time inside the loop comes from the TSC, calibrated against
// QPC before the loop starts.
//
// Review 2026-11-14:
// - V5: `threads` > 1 runs the loop on that many threads (each at
//   rate / threads), so several Rings are collected at once.
// - V6: a paced loop that is ahead of schedule by more than a few
//   milliseconds sleeps instead of spinning, like an application that rests
//   between bursts. Each Sleep is one captured call (two events); the count
//   is reported so the expected event count stays exact.
// - Interim review P1 (event accounting): every captured API call is also
//   counted by the workload itself, per API, as it returns ("calls" in
//   measurement.json). The script compares those counts with the Trace's
//   per-API event counts instead of an estimate derived from iterations.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned kMaxSeconds = 120;
static const unsigned kMaxThreads = 16;
static const unsigned kBatch = 64;

struct Shared {
    unsigned seconds;
    bool unpaced;
    unsigned long long rate;  // per thread
    unsigned long long tsc_rate;
    unsigned long long tsc_start;
    unsigned long long tsc_end;
    HANDLE heap;
    volatile long long per_second[kMaxSeconds];
    volatile long long total;
    volatile long long sleeps;
    // Independent per-API call counts (each incremented as the call returns).
    volatile long long calls_pid;
    volatile long long calls_alloc;
    volatile long long calls_free;
    volatile long long calls_sleep;
    volatile long checksum;
    volatile long failure;
};

static DWORD run_loop(Shared* s) {
    unsigned long long total = 0, sleeps = 0;
    unsigned long long n_pid = 0, n_alloc = 0, n_free = 0;
    unsigned checksum = 0;
    // Sleep only when this far ahead: well above one timer tick of work.
    const unsigned long long sleep_ahead = s->unpaced ? 0 : s->rate / 200 + kBatch;
    for (;;) {
        const unsigned long long tsc = __rdtsc();
        if (tsc >= s->tsc_end) break;
        const unsigned long long elapsed = tsc - s->tsc_start;
        if (!s->unpaced) {
            // Pace in batches: run only while behind the target schedule.
            const unsigned long long due =
                (unsigned long long)((double)elapsed * (double)s->rate / (double)s->tsc_rate);
            if (total >= due) {
                if (total - due >= sleep_ahead) {
                    Sleep(1);
                    ++sleeps;
                } else {
                    YieldProcessor();
                }
                continue;
            }
        }
        for (unsigned i = 0; i < kBatch; ++i) {
            const DWORD pid = GetCurrentProcessId();
            ++n_pid;
            if (pid == 0) { s->failure = 5; return 5; }
            auto* block = (volatile unsigned*)HeapAlloc(s->heap, 0, 64);
            ++n_alloc;
            if (!block) { s->failure = 6; return 6; }
            *block = (unsigned)total + i;
            checksum ^= *block;
            const BOOL freed = HeapFree(s->heap, 0, (void*)block);
            ++n_free;
            if (!freed) { s->failure = 7; return 7; }
        }
        total += kBatch;
        const unsigned bucket = (unsigned)(elapsed / s->tsc_rate);
        if (bucket < s->seconds) _InterlockedExchangeAdd64(&s->per_second[bucket], kBatch);
    }
    _InterlockedExchangeAdd64(&s->total, (long long)total);
    _InterlockedExchangeAdd64(&s->sleeps, (long long)sleeps);
    _InterlockedExchangeAdd64(&s->calls_pid, (long long)n_pid);
    _InterlockedExchangeAdd64(&s->calls_alloc, (long long)n_alloc);
    _InterlockedExchangeAdd64(&s->calls_free, (long long)n_free);
    _InterlockedExchangeAdd64(&s->calls_sleep, (long long)sleeps);
    _InterlockedXor(&s->checksum, (long)checksum);
    return 0;
}

static DWORD WINAPI thread_main(void* arg) { return run_loop((Shared*)arg); }

static Shared g_shared;

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) return 2;
    const unsigned seconds = (unsigned)strtoul(argv[1], nullptr, 10);
    if (seconds == 0 || seconds > kMaxSeconds) return 2;
    const bool unpaced = strcmp(argv[2], "max") == 0;
    const unsigned long long rate = unpaced ? 0 : strtoull(argv[2], nullptr, 10);
    if (!unpaced && rate == 0) return 2;
    const unsigned threads = argc == 4 ? (unsigned)strtoul(argv[3], nullptr, 10) : 1;
    if (threads == 0 || threads > kMaxThreads) return 2;
    LARGE_INTEGER frequency, calibrate_start, calibrate_end, start, now;
    if (!QueryPerformanceFrequency(&frequency)) return 3;
    const long long f = frequency.QuadPart;
    // TSC ticks per second, over ~100 ms.
    if (!QueryPerformanceCounter(&calibrate_start)) return 3;
    const unsigned long long tsc_calibrate = __rdtsc();
    Sleep(100);
    if (!QueryPerformanceCounter(&calibrate_end)) return 3;
    g_shared.calls_sleep = 1;  // the calibration Sleep is captured too
    const unsigned long long tsc_rate =
        (unsigned long long)((double)(__rdtsc() - tsc_calibrate) * (double)f /
                             (double)(calibrate_end.QuadPart - calibrate_start.QuadPart));
    if (tsc_rate == 0) return 3;
    Shared* s = &g_shared;
    s->seconds = seconds;
    s->unpaced = unpaced;
    s->rate = unpaced ? 0 : (rate + threads - 1) / threads;
    s->tsc_rate = tsc_rate;
    s->heap = GetProcessHeap();
    HANDLE workers[kMaxThreads] = {};
    if (!QueryPerformanceCounter(&start)) return 3;
    s->tsc_start = __rdtsc();
    s->tsc_end = s->tsc_start + (unsigned long long)seconds * tsc_rate;
    // Extra threads start before the main thread's loop; their creation
    // calls are outside the expected count, like startup.
    for (unsigned t = 1; t < threads; ++t) {
        workers[t] = CreateThread(nullptr, 0, thread_main, s, 0, nullptr);
        if (!workers[t]) return 10;
    }
    run_loop(s);
    for (unsigned t = 1; t < threads; ++t) {
        if (WaitForSingleObject(workers[t], INFINITE) != WAIT_OBJECT_0) return 11;
        CloseHandle(workers[t]);
    }
    if (s->failure) return (int)s->failure;
    if (!QueryPerformanceCounter(&now)) return 4;
    FILE* output = nullptr;
    if (fopen_s(&output, "measurement.json", "w") != 0) return 8;
    fprintf(output, "{\"seconds\":%u,\"rate\":%llu,\"threads\":%u,\"iterations\":%lld,"
                    "\"sleeps\":%lld,\"ticks\":%lld,\"qpc_frequency\":%lld,\"checksum\":%lu,"
                    "\"calls\":{\"GetCurrentProcessId\":%lld,\"HeapAlloc\":%lld,"
                    "\"HeapFree\":%lld,\"Sleep\":%lld},\"per_second\":[",
            seconds, rate, threads, s->total, s->sleeps, now.QuadPart - start.QuadPart, f,
            (unsigned long)s->checksum, s->calls_pid, s->calls_alloc, s->calls_free,
            s->calls_sleep);
    for (unsigned i = 0; i < seconds; ++i) {
        fprintf(output, i ? ",%lld" : "%lld", s->per_second[i]);
    }
    fprintf(output, "]}\n");
    if (fclose(output) != 0) return 9;
    return 0;
}
