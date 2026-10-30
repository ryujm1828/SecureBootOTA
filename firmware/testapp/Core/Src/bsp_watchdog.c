/**
  ******************************************************************************
  * @file           : bsp_watchdog.c
  * @brief          : Watchdog feed and firmware confirmation implementation
  ******************************************************************************
  */

#include "bsp_watchdog.h"

void System_Feed_Watchdog(void)
{
    // Reload IWDG counter
    IWDG->KR = 0xAAAA;
}

void System_Confirm_Firmware(void)
{
    // Enable PWR clock and enable write access to RTC Backup domain
    RCC->APB1ENR |= RCC_APB1ENR_PWREN;
    PWR->CR |= PWR_CR_DBP;

    // Write confirmation token to backup register
    RTC->BKP0R = BOOT_CONFIRM_KEY;
}