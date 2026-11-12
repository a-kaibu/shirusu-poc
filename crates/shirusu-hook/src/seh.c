#include <windows.h>
#include <stdint.h>

typedef uint64_t (__cdecl *invoke_fn)(void *);
typedef void (__cdecl *cleanup_fn)(void *);

// Observe actual stack unwinding, not first-chance exceptions. Do not catch,
// translate, or re-raise: the caller retains the original exception/context.
uint64_t __cdecl shirusu_invoke_with_finally(
    invoke_fn invoke, void *context, cleanup_fn cleanup)
{
    __try {
        return invoke(context);
    } __finally {
        if (AbnormalTermination()) cleanup(context);
    }
}

// Native regression harness. Unreferenced helpers are discarded from the DLL.
uint64_t __cdecl shirusu_test_raise_seh(void) {
    RaiseException(0xe0424242, 0, 0, NULL);
    return 0;
}
uint32_t __cdecl shirusu_test_catch_seh(invoke_fn invoke, void *context) {
    __try { invoke(context); return 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}
