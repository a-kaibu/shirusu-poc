#ifndef SHIRUSU_CALLSITE_H
#define SHIRUSU_CALLSITE_H
#include <stdint.h>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

struct shirusu_callsite_frame {
    uintptr_t address;
    uint32_t api_id;
};
const struct shirusu_callsite_frame * __cdecl shirusu_swap_callsite(
    const struct shirusu_callsite_frame *frame);
#endif
