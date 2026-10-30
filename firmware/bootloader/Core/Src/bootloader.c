/**
  ******************************************************************************
  * @file           : bootloader.c
  * @brief          : Secure Bootloader Verification and Jump Logic
  ******************************************************************************
  */

#include "bootloader.h"
#include "secure_utils.h"
#include "w25q64.h"
#include "ota_manager.h"
#include "sha256.h"
#include "uECC.h"
#include "boot_watchdog.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief  Verify the OTA header structure and its fields.
 * @retval 1: Valid, 0: Error
 */
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
  return 1;
}

/**
 * @brief  Verify the stored firmware in flash (header and app binary)
 * @retval 1: Valid, 0: Error
 */
int verify_stored_firmware(uint32_t header_address, uint32_t app_address)
{
  const ota_header_t *hdr = (const ota_header_t *)header_address;

  if (!validate_ota_header(hdr)) {
    return 0;
  }

  uint8_t header_hash[32];
  SHA256_CTX sha_ctx;
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, (const uint8_t *)header_address, 56);
  sha256_final(&sha_ctx, header_hash);
  uint32_t sig_status = SEC_FALSE;
  uint32_t flow_token = 0;
  
  if (uECC_verify(ecdsa_public_key, header_hash, 32, hdr->signature, uECC_secp256r1()) == 1) {
    sig_status = SEC_TRUE;
    flow_token += 0x11111111;
  }
  else {
    printf("[SECURITY] ECDSA Signature Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  uint8_t app_hash[32];
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, (const uint8_t *)app_address, hdr->image_size);
  sha256_final(&sha_ctx, app_hash);

  // Constant-time compare for payload hash
  if (constant_time_memcmp(app_hash, hdr->payload_sha256, 32) == 0) {
    flow_token += 0x22222222;
  }
  else {
    printf("[SECURITY] App SHA-256 Hash Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  if (sig_status == SEC_TRUE && flow_token == 0x33333333) {
    if (sig_status != SEC_FALSE) {
      printf("[SECURITY] Firmware verification successful! flow_token: 0x%08lX\r\n", (unsigned long)flow_token);
      return 1;
    }
  }
  else {
    printf("[SECURITY] Firmware verification failed! flow_token: 0x%08lX\r\n", (unsigned long)flow_token);
    return 0;
  }

  while (1) { __disable_irq(); }
  return 0;
}

/**
 * @brief  Verify staging firmware in external flash
 * @retval 1: Valid, 0: Error
 */
int verify_staging_firmware(uint32_t ext_header_address)
{
  ota_header_t hdr;

  W25Q64_ReadData(ext_header_address, (uint8_t *)&hdr, sizeof(ota_header_t));

  if (!validate_ota_header(&hdr)) {
    printf("[OTA ERROR] Invalid OTA header in staging area.\r\n");
    return 0;
  }

  if (hdr.image_size == 0 || hdr.image_size > MAX_APP_BINARY_SIZE) {
    printf("[OTA ERROR] Invalid image size: %lu bytes\r\n", (unsigned long)hdr.image_size);
    return 0;
  }

  const ota_header_t *installed_hdr = (const ota_header_t *)HEADER_START_ADDRESS;
  if (installed_hdr->magic == EXPECTED_MAGIC && hdr.image_version < installed_hdr->image_version) {
    printf("[OTA ERROR] New image version (%lu) is not greater than installed version (%lu).\r\n", 
           (unsigned long)hdr.image_version, (unsigned long)installed_hdr->image_version);
    return 0;
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
  }
  else {
    printf("[OTA ERROR] ECDSA Signature Mismatch in OTA header! Firmware Rejected.\r\n");
    return 0;
  }

  uint8_t app_hash[32];
  sha256_init(&sha_ctx);

  uint32_t app_address = ext_header_address + sizeof(ota_header_t);
  uint32_t remaining = hdr.image_size;
  uint8_t chunk[256];

  while (remaining > 0) {
    uint16_t read_size = (remaining > sizeof(chunk)) ? sizeof(chunk) : remaining;
    W25Q64_ReadData(app_address, chunk, read_size);
    sha256_update(&sha_ctx, chunk, read_size);
    app_address += read_size;
    remaining -= read_size;
  }
  sha256_final(&sha_ctx, app_hash);

  // Constant-time compare for payload hash
  if (constant_time_memcmp(app_hash, hdr.payload_sha256, 32) == 0) {
    flow_token += 0x22222222;
  }
  else {
    printf("[OTA ERROR] App SHA-256 Hash Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  if (sig_status == SEC_TRUE && flow_token == 0x33333333) {
    if (sig_status != SEC_FALSE) {
      return 1;
    }
  }
  else {
    printf("[OTA ERROR] Staging firmware verification failed! flow_token: 0x%08lX\r\n", (unsigned long)flow_token);
    return 0;
  }
  
  while (1) { __disable_irq(); }
  
  return 0;
}

/**
 * @brief  Jump to the application at the specified address.
 */
void jump_to_application(uint32_t app_address)
{
  printf("Valid App found. Jumping to App at 0x%08lX...\r\n", (unsigned long)app_address);
  HAL_Delay(50); // Delay to ensure UART transmission completes

  __disable_irq();

  SysTick->CTRL = 0;
  SysTick->LOAD = 0;
  SysTick->VAL = 0;

  HAL_DeInit();

  for (int i = 0; i < 8; i++) {
    NVIC->ICER[i] = 0xFFFFFFFF;
    NVIC->ICPR[i] = 0xFFFFFFFF;
  }

  uint32_t jump_address = *(__IO uint32_t *)(app_address + 4);
  void (*app_reset_handler)(void) = (void (*)(void))jump_address;
  SCB->VTOR = app_address;
  __set_MSP(*(__IO uint32_t *)app_address);
  app_reset_handler();
}

/**
 * @brief  Main bootloader logic routine.
 */
void bootloader_run(void)
{
  if (watchdog_was_reset_by_iwdg()) 
    printf("[WARNING] System rebooted due to IWDG WATCHDOG TIMEOUT!\r\n");

  printf("\r\n===========================\r\n");
  printf("Secure Bootloader Started\r\n");
  printf("Checking App at Address: 0x%08lX\r\n", (unsigned long)APP_START_ADDRESS);

  // Print device UID info
  uint8_t hw_uid[12];
  memcpy(hw_uid, (const void *)STM32_UID_BASE, 12);
  printf("STM32 Hardware UID : ");
  for (int i = 0; i < 12; i++) printf("%02X", hw_uid[i]);
  printf("\r\n");
#if !USE_REAL_DEVICE_UID
  printf("Note: Using Sample UID (00112233445566778899AABB) for HKDF.\r\n");
#endif
  
  // Enter OTA mode if the user button (B1) is pressed during boot
  if (HAL_GPIO_ReadPin(B1_GPIO_Port, B1_Pin) == GPIO_PIN_RESET) {
    printf("[BOOT] User Button (B1) pressed! Entering OTA Mode...\r\n");
    int ota_status = wait_for_ota_package();
    if (ota_status == OTA_STATUS_TIMEOUT) {
      printf("[BOOT] OTA timeout (no update). Falling back to boot existing App...\r\n");
    } else {
      printf("[BOOT] OTA session ended (status: %d). Checking existing App...\r\n", ota_status);
    }
  }
  
  // Verify the stored firmware (header and app binary)
  if (verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
    printf("[BOOT] Starting Watchdog (8 seconds timeout)...\r\n");
    watchdog_start(8000);
    // Check if the MSP (Main Stack Pointer) value is valid (should be in SRAM range)
    if (((*(__IO uint32_t*)APP_START_ADDRESS) & 0x2FF00000) == 0x20000000) {
      jump_to_application(APP_START_ADDRESS);
    } else {
      printf("BOOT ERROR: Invalid MSP address. Entering RECOVERY mode.\r\n");
      while (1) {
        printf("Waiting for new OTA package...\r\n");
        wait_for_ota_package();
      }
    }
  } else {
    printf("No valid/verified App found. Entering RECOVERY mode.\r\n");
    while (1) {
      printf("Waiting for new OTA package...\r\n");
      wait_for_ota_package();
    }
  }
}

