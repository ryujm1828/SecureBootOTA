#ifndef __BOOT_CLIENT_H
#define __BOOT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"

/* ========================================================================== */
/* Bootloader State Tokens (Must match boot_config.h in bootloader)          */
/* ========================================================================== */
#define BOOT_STATE_NORMAL   0xA5A5A5A5U
#define BOOT_STATE_TESTING  0x5A5A5A5AU

/* ========================================================================== */
/* Watchdog Keys                                                              */
/* ========================================================================== */
#define IWDG_RELOAD_KEY     0xAAAAU

/**
 * @brief  Confirm successful boot to the bootloader (Self-Confirmation).
 *         Transitions state from BOOT_STATE_TESTING to BOOT_STATE_NORMAL.
 */
void boot_client_confirm(void);

/**
 * @brief  Feed (refresh) the independent hardware watchdog (IWDG).
 */
void boot_client_feed_watchdog(void);

#ifdef __cplusplus
}
#endif

#endif /* __BOOT_CLIENT_H */


#ifdef __cplusplus
}
#endif

#endif /* __BOOT_CLIENT_H */