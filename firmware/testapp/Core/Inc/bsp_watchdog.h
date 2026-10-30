/**
  ******************************************************************************
  * @file           : bsp_watchdog.h
  * @brief          : Watchdog feed and firmware confirmation utilities
  ******************************************************************************
  */

#ifndef __BSP_WATCHDOG_H
#define __BSP_WATCHDOG_H

#include "stm32f4xx.h"
#include <stdint.h>

#define BOOT_CONFIRM_KEY 0xA55A5AA5U

/**
 * @brief  Feed the Independent Watchdog (IWDG) to prevent a system reset.
 */
void System_Feed_Watchdog(void);

/**
 * @brief  Confirm firmware is healthy and promote state to NORMAL.
 */
void System_Confirm_Firmware(void);

#endif /* __BSP_WATCHDOG_H */
