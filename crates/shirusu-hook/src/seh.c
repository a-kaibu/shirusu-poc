#include <windows.h>
#include <stdint.h>
#include "callsite.h"

typedef uint64_t (__cdecl *invoke_fn)(void *);
typedef void (__cdecl *cleanup_fn)(void *);

// Observe actual stack unwinding, not first-chance exceptions. Do not catch,
// translate, or re-raise: the caller retains the original exception/context.
uint64_t __cdecl shirusu_invoke_with_finally(
    invoke_fn invoke, void *context, cleanup_fn cleanup)
{
    uint64_t result;
    __try {
        result = invoke(context);
    } __finally {
        if (AbnormalTermination()) cleanup(context);
    }
    return result;
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

// _ReturnAddress must be evaluated in the actual entry wrapper, not in a
// called helper. Typed API wrappers will use this same native-frame protocol.
uint64_t __cdecl shirusu_test_with_callsite(
    uint32_t api_id, invoke_fn invoke, void *context)
{
    struct shirusu_callsite_frame frame = {(uintptr_t)_ReturnAddress(), api_id};
    const struct shirusu_callsite_frame *previous = shirusu_swap_callsite(&frame);
    uint64_t result;
    __try { result = invoke(context); }
    __finally { shirusu_swap_callsite(previous); }
    return result;
}
