#include "boot_client.h"

void boot_client_confirm(void)
{
  // 1. PWR 클럭 활성화
  __HAL_RCC_PWR_CLK_ENABLE();

  // 2. RTC 및 Backup 레지스터 쓰기 보호(락) 해제
  PWR->CR |= PWR_CR_DBP;

  // 3. 펌웨어 정상 확정 마크(BOOT_STATE_NORMAL) 기록
  RTC->BKP1R = BOOT_STATE_NORMAL;

  // 4. 쓰기 보호(락) 다시 잠그기
  PWR->CR &= ~PWR_CR_DBP;
}

void boot_client_feed_watchdog(void)
{
  // 독립 워치독 갱신 (리로드)
  IWDG->KR = IWDG_RELOAD_KEY;
}
