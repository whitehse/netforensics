/**
 * @file cpe_agent_sim.h
 * @brief Optional libsim class-B drive for CPE agent (P2.7b).
 *
 * Uses sim_clock + sim_timer only (no uring). Soft dependency.
 */
#ifndef CPE_AGENT_SIM_H
#define CPE_AGENT_SIM_H

#include "cpe_agent.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Drive agent demo ticks with virtual time from a fuzz / test byte stream.
 * Interprets remaining bytes as: [count_u8] then for each tick advance_ms_u16.
 * Safe on empty input. Always returns 0 (crash = failure).
 */
int cpe_agent_sim_drive(cpe_agent_t *a, const uint8_t *data, size_t size);

/**
 * Convenience: create agent, apply defaults, drive, destroy.
 * Used by fuzz entry points.
 */
int cpe_agent_sim_drive_standalone(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_SIM_H */
