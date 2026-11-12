#include "boot_watchdog.h"
#include "stm32f4xx_hal.h"

#define BOOT_BKP_MAGIC 0xB0070000U

void watchdog_start(uint32_t timeout_ms)
{
    uint32_t reload = (timeout_ms / 8U);
    if (reload > 0xFFFU) {
        reload = 0xFFFU;
    }

    IWDG->KR = IWDG_KEY_ENABLE;
    IWDG->KR = IWDG_KEY_WRITE_EN;
    IWDG->PR = 0x06;
    IWDG->RLR = (uint16_t)reload;
    while ((IWDG->SR & (IWDG_SR_PVU | IWDG_SR_RVU))!= 0U){} /*wait*/
    IWDG->KR = IWDG_KEY_RELOAD;
}

int watchdog_was_reset_by_iwdg(void)
{
    return (RCC->CSR & RCC_CSR_IWDGRSTF) ? 1 : 0;
}

uint32_t watchdog_get_boot_fail_count(void)
{
    __HAL_RCC_PWR_CLK_ENABLE();
    PWR->CR |= PWR_CR_DBP;
    uint32_t val = RTC->BKP0R;
    if ((val & 0xFFFF0000U) == BOOT_BKP_MAGIC) {
        return (val & 0x0000FFFFU);
    }
    return 0;
}

void watchdog_set_boot_fail_count(uint32_t count)
{
    __HAL_RCC_PWR_CLK_ENABLE();
    PWR->CR |= PWR_CR_DBP;
    RTC->BKP0R = BOOT_BKP_MAGIC | (count & 0x0000FFFFU);
}

void watchdog_clear_boot_fail_count(void)
{
    __HAL_RCC_PWR_CLK_ENABLE();
    PWR->CR |= PWR_CR_DBP;
    RTC->BKP0R = BOOT_BKP_MAGIC;
}

void watchdog_clear_reset_flags(void)
{
    RCC->CSR |= RCC_CSR_RMVF;
}