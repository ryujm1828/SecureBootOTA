#ifndef __BOOT_WATCHDOG_H
#define __BOOT_WATCHDOG_H

#include "stm32f4xx.h"
#include <stdint.h>

/* IWDG 키 레지스터 값 */
#define IWDG_KEY_RELOAD    0xAAAAU  // Reload the watchdog counter
#define IWDG_KEY_ENABLE    0xCCCCU  // Start the watchdog
#define IWDG_KEY_WRITE_EN  0x5555U  // Enable write access to IWDG_PR and IWDG_RLR registers

/**
 * @brief  IWDG watchdog start
 * @param  timeout_ms: Timeout time
 */
void watchdog_start(uint32_t timeout_ms);

/**
 * @brief  IWDG watchdog refresh (kick/feed) to prevent reset
 */
static inline void watchdog_refresh(void) {
    IWDG->KR = IWDG_KEY_RELOAD;
}

/**
 * @brief  Check if the last reset was caused by the Independent Watchdog (IWDG)
 * @retval 1: IWDG Reset, 0: Not IWDG Reset
 */
int watchdog_was_reset_by_iwdg(void);

#endif /* __BOOT_WATCHDOG_H */