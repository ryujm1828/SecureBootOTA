#include "boot_client.h"

void boot_client_confirm(void)
{
    __HAL_RCC_PWR_CLK_ENABLE();
    PWR->CR |= PWR_CR_DBP;
    if (RTC->BKP1R == BOOT_STATE_TESTING) {
    uint8_t cur_slot = (uint8_t)RTC->BKP2R;
        uint8_t new_slot = (cur_slot == BOOT_SLOT_B) ? BOOT_SLOT_A : BOOT_SLOT_B;
        RTC->BKP2R = new_slot;          
        RTC->BKP1R = BOOT_STATE_NORMAL;   
    }
    PWR->CR &= ~PWR_CR_DBP;
}

void boot_client_feed_watchdog(void)
{
  // 독립 워치독 갱신 (리로드)
  IWDG->KR = IWDG_RELOAD_KEY;
}
