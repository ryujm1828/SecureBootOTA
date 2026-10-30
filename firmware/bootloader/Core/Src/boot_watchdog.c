#include "boot_watchdog.h"

void watchdog_start(uint32_t timeout_ms)
{
    // LSI Clock = 32 kHz
    // Prescaler 256 : 1 Count = 256 / 32000 = 8ms
    uint32_t reload = (timeout_ms / 8);
    if (reload > 0xFFF) {
        reload = 0xFFF; // 12-bit 최대값 (4095)
    }

    // Enable write access to IWDG_PR and IWDG_RLR registers
    IWDG->KR = IWDG_KEY_WRITE_EN;

    // Set prescaler to 256 (IWDG_PR = 0x06)
    IWDG->PR = 0x06;

    // Set reload value
    IWDG->RLR = (uint16_t)reload;

    // Load the IWDG counter with the reload value (kick/feed)
    IWDG->KR = IWDG_KEY_RELOAD;

    // Start the IWDG
    IWDG->KR = IWDG_KEY_ENABLE;
}

int watchdog_was_reset_by_iwdg(void)
{
    // Check if the Independent Watchdog Reset Flag is set
    if (RCC->CSR & RCC_CSR_IWDGRSTF) {
        // Clear the reset flags for future checks
        RCC->CSR |= RCC_CSR_RMVF;
        return 1; 
    }
    return 0;
}