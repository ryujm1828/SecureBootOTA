#include "bootloader.h"
#include "secure_utils.h"
#include "w25q64.h"
#include "ota_manager.h"
#include "sha256.h"
#include "uECC.h"
#include "boot_watchdog.h"
#include <stdio.h>
#include <string.h>

int validate_ota_header(const ota_header_t *header)
{
  if (header->magic != EXPECTED_MAGIC) {
    printf("[ERROR] Invalid magic in OTA header. Expected: 0x%08lX, Got: 0x%08lX\r\n", 
           (unsigned long)EXPECTED_MAGIC, (unsigned long)header->magic);
    return 0;
  }
  if (header->format_version != EXPECTED_FORMAT_VERSION) {
    printf("[ERROR] Unsupported format version: 0x%04X\r\n", header->format_version);
    return 0;
  }
  if (header->header_size != EXPECTED_HEADER_SIZE) {
    printf("[ERROR] Unexpected header size: %d\r\n", header->header_size);
    return 0;
  }
  if (header->target_id != EXPECTED_TARGET_ID) {
    printf("[ERROR] Target ID mismatch. Expected: 0x%08lX, Got: 0x%08lX\r\n", 
           (unsigned long)EXPECTED_TARGET_ID, (unsigned long)header->target_id);
    return 0;
  }
  if (header->image_size == 0 || header->image_size > MAX_APP_BINARY_SIZE) {
    printf("[ERROR] Invalid image size: %lu bytes\r\n", (unsigned long)header->image_size);
    return 0;
  }
  return 1;
}

typedef void (*firmware_read_fn)(uint32_t src_addr, uint8_t *dst, uint32_t len);

static void read_internal_memory(uint32_t src_addr, uint8_t *dst, uint32_t len)
{
  memcpy(dst, (const void *)src_addr, len);
}

static void read_external_flash(uint32_t src_addr, uint8_t *dst, uint32_t len)
{
  W25Q64_ReadData(src_addr, dst, len);
}

static int verify_firmware_common(uint32_t header_address, uint32_t app_address, firmware_read_fn read_fn, int check_rollback)
{
  ota_header_t hdr;
  read_fn(header_address, (uint8_t *)&hdr, sizeof(ota_header_t));

  if (!validate_ota_header(&hdr)) {
    return 0;
  }

  if (hdr.image_size == 0 || hdr.image_size > MAX_APP_BINARY_SIZE) {
    printf("[SECURITY] Invalid image size: %lu bytes\r\n", (unsigned long)hdr.image_size);
    return 0;
  }

  if (read_fn == read_internal_memory) {
    if (app_address < APP_START_ADDRESS || 
        (app_address + hdr.image_size) > (APP_START_ADDRESS + MAX_APP_BINARY_SIZE) || 
        (app_address + hdr.image_size) < app_address) {
      printf("[SECURITY] App address range error: 0x%08lX + %lu\r\n", 
             (unsigned long)app_address, (unsigned long)hdr.image_size);
      return 0;
    }
  } else{
    // Check external memory
    if (app_address >= EXT_FLASH_SIZE ||
        (app_address + hdr.image_size) > EXT_FLASH_SIZE ||
        (app_address + hdr.image_size) < app_address) {
        printf("[SECURITY] Ext flash address range error: 0x%08lX + %lu\r\n",
               (unsigned long)app_address, (unsigned long)hdr.image_size);
        return 0;
    }
  }

  if (check_rollback) {
    const ota_header_t *installed_hdr = (const ota_header_t *)HEADER_START_ADDRESS;
    if (installed_hdr->magic == EXPECTED_MAGIC && hdr.image_version < installed_hdr->image_version) {
      printf("[SECURITY] New image version (%lu) is not greater than installed version (%lu).\r\n", 
             (unsigned long)hdr.image_version, (unsigned long)installed_hdr->image_version);
      return 0;
    }
  }

  uint8_t header_hash[32];
  SHA256_CTX sha_ctx;
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, (const uint8_t *)&hdr, 56);
  sha256_final(&sha_ctx, header_hash);

  uint32_t sig_status = SEC_FALSE;
  uint32_t flow_token = 0;

  if (uECC_verify(ecdsa_public_key, header_hash, 32, hdr.signature, uECC_secp256r1()) == 1) {
    sig_status = SEC_TRUE;
    flow_token += 0x11111111;
  } else {
    printf("[SECURITY] ECDSA Signature Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  uint8_t app_hash[32];
  sha256_init(&sha_ctx);

  uint32_t cur_addr = app_address;
  uint32_t remaining = hdr.image_size;
  uint8_t chunk[256];

  while (remaining > 0) {
    uint16_t read_size = (remaining > sizeof(chunk)) ? sizeof(chunk) : (uint16_t)remaining;
    read_fn(cur_addr, chunk, read_size);
    sha256_update(&sha_ctx, chunk, read_size);
    cur_addr += read_size;
    remaining -= read_size;
  }
  sha256_final(&sha_ctx, app_hash);

  if (constant_time_memcmp(app_hash, hdr.payload_sha256, 32) == 0) {
    flow_token += 0x22222222;
  } else {
    printf("[SECURITY] App SHA-256 Hash Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  if (sig_status == SEC_TRUE && flow_token == 0x33333333)
    return 1;

  return 0;
}

int verify_stored_firmware(uint32_t header_address, uint32_t app_address)
{
  // Validate OTA header and firmware in internal flash, including rollback protection
  if (!verify_firmware_common(header_address, app_address, read_internal_memory, 0)) {
    return 0;
  }
  // 2. Check MSP and Reset Handler in the App's vector table
  uint32_t msp_val = *(__IO uint32_t *)app_address;
  uint32_t reset_handler = *(__IO uint32_t *)(app_address + 4);
  // Check that MSP is in SRAM range (0x20000000 - 0x200FFFFF) and Reset Handler is odd (Thumb mode)
  if (((msp_val & 0xFFF00000) != 0x20000000) || ((reset_handler & 1) == 0)) {
    printf("[SECURITY] Invalid MSP (0x%08lX) or Reset Handler (0x%08lX)!\r\n", 
           (unsigned long)msp_val, (unsigned long)reset_handler);
    return 0;
  }
  return 1;
}

int verify_staging_firmware(uint32_t ext_header_address)
{
  return verify_firmware_common(ext_header_address, ext_header_address + sizeof(ota_header_t), read_external_flash, 1);
}

void jump_to_application(uint32_t app_address)
{ 
  printf("Jumping to App at 0x%08lX...\r\n", (unsigned long)app_address);
  while (!(USART2->SR & USART_SR_TC));
  uint32_t msp_val = *(__IO uint32_t *)app_address;
  uint32_t reset_handler = *(__IO uint32_t *)(app_address + 4);

  __disable_irq();

  SysTick->CTRL = 0;
  SysTick->LOAD = 0;
  SysTick->VAL = 0;
  SCB->ICSR = SCB_ICSR_PENDSTCLR_Msk;
  
  for (int i = 0; i < 8; i++) {
    NVIC->ICER[i] = 0xFFFFFFFF;
    NVIC->ICPR[i] = 0xFFFFFFFF;
  }
  
  HAL_DeInit();

  // Switch system clock to HSI (16 MHz) before jumping to App
  RCC->CR |= RCC_CR_HSION;
  while ((RCC->CR & RCC_CR_HSIRDY) == 0);
  RCC->CFGR &= ~RCC_CFGR_SW; 
  while ((RCC->CFGR & RCC_CFGR_SWS) != RCC_CFGR_SWS_HSI);
  RCC->CR &= ~RCC_CR_PLLON; 
  RCC->CFGR = 0x00000000;    

  SCB->VTOR = app_address;
  
  __asm volatile (
        "msr msp, %0 \n"  // Set Main Stack Pointer
        "bx %1       \n"  // Jump to Reset_Handler
        :
        : "r" (msp_val), "r" (reset_handler)
        : "memory"
    );
    while (1);
}

static void enter_recovery_mode(const char *reason)
{
  printf("[RECOVERY] %s. Waiting for new OTA package...\r\n", reason);
  while (1) {
    int status = wait_for_ota_package();
    if (status == OTA_STATUS_OK) {

      watchdog_clear_boot_fail_count();
      printf("[RECOVERY] Update installed! Rebooting system...\r\n");
      HAL_Delay(100);
      NVIC_SystemReset();
    }
  }
}

void bootloader_run(void)
{
  int bootloop_detected = 0;
  int was_iwdg_reset = watchdog_was_reset_by_iwdg();

  if (was_iwdg_reset) {
    uint32_t fail_count = watchdog_get_boot_fail_count() + 1;
    watchdog_set_boot_fail_count(fail_count);
    printf("[WARNING] System rebooted due to IWDG WATCHDOG TIMEOUT! (Fail count: %lu)\r\n", (unsigned long)fail_count);
    if (fail_count >= 3) {
      bootloop_detected = 1;
      printf("[SECURITY] Bootloop detected! Watchdog failed %lu times consecutively. Entering RECOVERY mode.\r\n", (unsigned long)fail_count);
    }
  } else {
    watchdog_clear_boot_fail_count();
  }

  watchdog_clear_reset_flags();

  printf("\r\n===========================\r\n");
  printf("Secure Bootloader Started\r\n");
  printf("Checking App at Address: 0x%08lX\r\n", (unsigned long)APP_START_ADDRESS);

  uint8_t hw_uid[12];
  memcpy(hw_uid, (const void *)STM32_UID_BASE, 12);
  printf("STM32 Hardware UID : ");
  for (int i = 0; i < 12; i++) printf("%02X", hw_uid[i]);
  printf("\r\n");
#if !USE_REAL_DEVICE_UID
  printf("Note: Using Sample UID (00112233445566778899AABB) for HKDF.\r\n");
#endif
  
  if (HAL_GPIO_ReadPin(B1_GPIO_Port, B1_Pin) == GPIO_PIN_RESET) {
    printf("[BOOT] User Button (B1) pressed! Entering OTA Mode...\r\n");
    int ota_status = wait_for_ota_package();
    if (ota_status == OTA_STATUS_OK) {
      watchdog_clear_boot_fail_count();
      printf("[BOOT] OTA update successful! Rebooting system...\r\n");
      HAL_Delay(100);
      NVIC_SystemReset();
    } else {
      printf("[BOOT] OTA timed out or aborted. Checking existing App...\r\n");
    }
  }
  
  if (bootloop_detected) {
    enter_recovery_mode("Bootloop detected! App crashed repeatedly");
  }

  if (verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
    printf("[BOOT] Firmware verified! Starting Watchdog (8s) & Booting...\r\n");
    watchdog_start(8000);
    jump_to_application(APP_START_ADDRESS);
  } else {
    enter_recovery_mode("No valid/verified App found");
  }
}
