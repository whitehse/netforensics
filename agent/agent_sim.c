/**
 * @file agent_sim.c
 * @brief libsim class-B drive: virtual clock + timer → demo ticks (P2.7b).
 */

#include "cpe_agent_sim.h"

#include "sim_clock.h"
#include "sim_timer.h"

#include <string.h>

int cpe_agent_sim_drive(cpe_agent_t *a, const uint8_t *data, size_t size)
{
    sim_clock_t *clk;
    sim_timer_mgr_t *tm;
    size_t pos = 0;
    unsigned ticks;
    unsigned i;

    if (!a) {
        return 0;
    }
    clk = sim_clock_create();
    if (!clk) {
        return 0;
    }
    tm = sim_timer_create(clk);
    if (!tm) {
        sim_clock_destroy(clk);
        return 0;
    }

    ticks = 1;
    if (data && size > 0) {
        ticks = (unsigned)(data[pos++] % 8u) + 1u; /* 1..8 ticks */
    }

    for (i = 0; i < ticks; i++) {
        uint64_t delay_ms = 10;
        uint64_t id;
        sim_timer_event_t tev;

        if (data && pos + 2 <= size) {
            delay_ms = (uint64_t)data[pos] | ((uint64_t)data[pos + 1] << 8);
            pos += 2;
            if (delay_ms == 0) {
                delay_ms = 1;
            }
            if (delay_ms > 60000) {
                delay_ms = 60000;
            }
        }
        id = sim_timer_schedule_after(tm, delay_ms * 1000000ull, NULL);
        (void)id;
        sim_clock_advance_ms(clk, delay_ms);
        while (sim_timer_next_event(tm, &tev) == 1) {
            if (tev.type == SIM_TIMER_EVENT_FIRED) {
                (void)cpe_agent_demo_ping_tick(a);
            }
        }
    }

    sim_timer_destroy(tm);
    sim_clock_destroy(clk);
    return 0;
}

int cpe_agent_sim_drive_standalone(const uint8_t *data, size_t size)
{
    cpe_agent_t *a;
    cpe_agent_config_t cfg;
    cpe_agent_event_t ev;

    a = cpe_agent_create();
    if (!a) {
        return 0;
    }
    cpe_agent_config_defaults(&cfg);
    cfg.demo_mode = 1;
    (void)cpe_agent_apply_config(a, &cfg);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    (void)cpe_agent_sim_drive(a, data, size);
    cpe_agent_destroy(a);
    return 0;
}
