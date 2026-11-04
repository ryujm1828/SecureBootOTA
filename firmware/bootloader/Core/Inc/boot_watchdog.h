#ifndef __BOOT_WATCHDOG_H
#define __BOOT_WATCHDOG_H

#include "stm32f4xx.h"
#include <stdint.h>

#define IWDG_KEY_RELOAD    0xAAAAU
#define IWDG_KEY_ENABLE    0xCCCCU
#define IWDG_KEY_WRITE_EN  0x5555U

void watchdog_start(uint32_t timeout_ms);

static inline void watchdog_refresh(void) {
    IWDG->KR = IWDG_KEY_RELOAD;
}

int watchdog_was_reset_by_iwdg(void);
uint32_t watchdog_get_boot_fail_count(void);
void watchdog_set_boot_fail_count(uint32_t count);
void watchdog_clear_boot_fail_count(void);
void watchdog_clear_reset_flags(void);

#endif
