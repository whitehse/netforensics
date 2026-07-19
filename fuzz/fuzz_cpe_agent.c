/**
 * libFuzzer entry for CPE agent (P2.7a/b).
 *
 * Default: local config+NDJSON stubs (no libsim required).
 * When CPE_AGENT_HAVE_LIBSIM: also drive sim clock/timer path.
 *
 * Build: cmake -B build-fuzz -S . -DBUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang
 */
#include "cpe_agent_fuzz.h"

#include <stddef.h>
#include <stdint.h>

#if defined(CPE_AGENT_HAVE_LIBSIM)
#include "cpe_agent_sim.h"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)cpe_agent_fuzz_config_and_ndjson(data, size);
#if defined(CPE_AGENT_HAVE_LIBSIM)
    (void)cpe_agent_sim_drive_standalone(data, size);
#endif
    return 0;
}
