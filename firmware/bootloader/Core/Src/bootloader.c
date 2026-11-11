#include "bootloader.h"
#include "secure_utils.h"
#include "w25q64.h"
#include "ota_manager.h"
#include "sha256.h"
#include "uECC.h"
#include "boot_watchdog.h"
#include "hkdf.h"
#include "aes.h"
#include "sha256.h"
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
  size_t signed_len = offsetof(ota_header_t, signature); 
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, (const uint8_t *)&hdr, signed_len);
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

int verify_encrypted_staging(uint32_t ext_slot_addr,int check_rollback){
  // Read Nonce, MAC
  uint8_t nonce[12];
  uint8_t rx_mac[16];
  W25Q64_ReadData(ext_slot_addr, nonce, 12);
  W25Q64_ReadData(ext_slot_addr + 12, rx_mac, 16);
  
  uint8_t device_key[32];
  derive_device_key(device_key);
  WORD round_keys[60];
  aes_key_setup(device_key, round_keys, 256);
  secure_memzero(device_key, sizeof(device_key));

  uint8_t header_buf[128];
  W25Q64_ReadData(ext_slot_addr + 28, header_buf, 128);
  uint8_t ctr[16] = {0x02};
  memcpy(&ctr[1], nonce, 12);
  uint8_t si[16];

  //Decrypt
  for (uint32_t b = 0; b < 8; b++) {
    uint32_t blk_cnt = b + 1;
    ctr[13] = (blk_cnt >> 16) & 0xFF;
    ctr[14] = (blk_cnt >> 8) & 0xFF;
    ctr[15] = blk_cnt & 0xFF;
    aes_encrypt(ctr, si, round_keys, 256);
    for (int i = 0; i < 16; i++) {
      header_buf[b * 16 + i] ^= si[i];
    }
  }
  ota_header_t hdr;
  memcpy(&hdr, header_buf, sizeof(ota_header_t));

  if (!validate_ota_header(&hdr)) {
    printf("[VERIFY ERROR] Invalid OTA Header format!\r\n");
    secure_memzero(round_keys, sizeof(round_keys));
    return 0;
  }

  //Anti rollback
  if(check_rollback){
    const ota_header_t *installed_hdr = (const ota_header_t *)HEADER_START_ADDRESS;
    if (installed_hdr->magic == EXPECTED_MAGIC && hdr.image_version < installed_hdr->image_version) {
      printf("[VERIFY ERROR] Anti-Rollback: Image version %lu is older than installed %lu!\r\n",
            (unsigned long)hdr.image_version, (unsigned long)installed_hdr->image_version);
      secure_memzero(round_keys, sizeof(round_keys));
      return 0;
    }  
  }
  

  // Verify ECDSA
  uint8_t header_hash[32];
  SHA256_CTX sha_ctx;
  size_t signed_len = offsetof(ota_header_t, signature);
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, (const uint8_t *)&hdr, signed_len);
  sha256_final(&sha_ctx, header_hash);
  if (uECC_verify(ecdsa_public_key, header_hash, 32, hdr.signature, uECC_secp256r1()) != 1) {
    printf("[VERIFY ERROR] ECDSA Signature Mismatch! Fake firmware.\r\n");
    secure_memzero(round_keys, sizeof(round_keys));
    return 0;
  }

  // Verify AES-CCM & SHA-256
  uint32_t plaintext_len = sizeof(ota_header_t) + hdr.image_size;
  uint8_t s0[16], b0[16] = {0x3A}, y[16];
  memset(ctr, 0, sizeof(ctr));
  ctr[0] = 0x02;
  memcpy(&ctr[1], nonce, 12);
  aes_encrypt(ctr, s0, round_keys, 256);
  memcpy(&b0[1], nonce, 12);
  b0[13] = (plaintext_len >> 16) & 0xFF;
  b0[14] = (plaintext_len >> 8) & 0xFF;
  b0[15] = plaintext_len & 0xFF;
  aes_encrypt(b0, y, round_keys, 256);
  SHA256_CTX app_sha_ctx;
  sha256_init(&app_sha_ctx);
  uint32_t remaining = plaintext_len;
  uint32_t src_addr = ext_slot_addr + 28;
  uint32_t block_counter = 1;
  uint32_t processed_plain = 0;
  uint8_t chunk[256];
  while (remaining > 0) {
    IWDG->KR = IWDG_KEY_RELOAD;
    uint16_t chunk_len = (remaining > sizeof(chunk)) ? sizeof(chunk) : (uint16_t)remaining;
    W25Q64_ReadData(src_addr, chunk, chunk_len);
    for (uint16_t offset = 0; offset < chunk_len; offset += 16) {
      uint16_t blk_len = (chunk_len - offset > 16) ? 16 : (chunk_len - offset);
      ctr[13] = (block_counter >> 16) & 0xFF;
      ctr[14] = (block_counter >> 8) & 0xFF;
      ctr[15] = block_counter & 0xFF;
      block_counter++;
      aes_encrypt(ctr, si, round_keys, 256);
      for (int b = 0; b < blk_len; b++) chunk[offset + b] ^= si[b];
      // CBC-MAC 
      uint8_t mac_in[16] = {0};
      memcpy(mac_in, &chunk[offset], blk_len);
      for (int b = 0; b < 16; b++) y[b] ^= mac_in[b];
      aes_encrypt(y, y, round_keys, 256);
    }
    //SHA-256 (APP Binary only)
    if (processed_plain >= sizeof(ota_header_t)) {
      sha256_update(&app_sha_ctx, chunk, chunk_len);
    } else if (processed_plain + chunk_len > sizeof(ota_header_t)) {
      uint16_t app_offset = sizeof(ota_header_t) - processed_plain;
      sha256_update(&app_sha_ctx, &chunk[app_offset], chunk_len - app_offset);
    }
    processed_plain += chunk_len;
    src_addr += chunk_len;
    remaining -= chunk_len;
  }

  // Verify AES-CCM MAC Tag
  uint8_t calculated_mac[16];
  for (int i = 0; i < 16; i++) calculated_mac[i] = y[i] ^ s0[i];
  if (constant_time_memcmp(calculated_mac, rx_mac, 16) != 0) {
    printf("[VERIFY ERROR] AES-CCM MAC Tag Mismatch! Ciphertext corrupted.\r\n");
    secure_memzero(round_keys, sizeof(round_keys));
    return 0;
  }

  // Verify SHA-256
  uint8_t calculated_app_hash[32];
  sha256_final(&app_sha_ctx, calculated_app_hash);
  if (constant_time_memcmp(calculated_app_hash, hdr.payload_sha256, 32) != 0) {
    printf("[VERIFY ERROR] Payload SHA-256 Mismatch!\r\n");
    secure_memzero(round_keys, sizeof(round_keys));
    return 0;
  }

  secure_memzero(round_keys, sizeof(round_keys));
  // Verify Success
  printf("[VERIFY SUCCESS] All 5 checks passed! (Header, Version, ECDSA, SHA-256, MAC)\r\n");
  return 1;
}

void jump_to_application(uint32_t app_address)
{ 
  const ota_header_t *hdr = (const ota_header_t *)HEADER_START_ADDRESS;
  printf("Jumping to App (Version: %lu) at 0x%08lX...\r\n", 
         (unsigned long)hdr->image_version, (unsigned long)app_address);
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

void derive_device_key(uint8_t key[32])
{
  uint8_t device_uid[12];
#if USE_REAL_DEVICE_UID
  memcpy(device_uid, (const void *)STM32_UID_BASE, 12);
#else
  const uint8_t sample_uid[12] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
  memcpy(device_uid, sample_uid, 12);
#endif
  hkdf_sha256(OTA_SALT, OTA_SALT_LEN,
              MASTER_KEY, MASTER_KEY_LEN,
              device_uid, 12,
              key, 32);
}

int install_firmware(uint32_t ext_slot_addr)
{
  // Read Nonce (12B), MAC Tag (16B)
  uint8_t nonce[12];
  uint8_t rx_mac[16];
  W25Q64_ReadData(ext_slot_addr, nonce, 12);
  W25Q64_ReadData(ext_slot_addr + 12, rx_mac,16);
  
  // AES Key
  uint8_t device_key[32];
  derive_device_key(device_key);
  WORD round_keys[60];
  aes_key_setup(device_key, round_keys, 256);

  // Get package size
  uint8_t first_chunk[128];
  W25Q64_ReadData(ext_slot_addr + 28, first_chunk, 128);

  uint8_t ctr[16] = {0x02};
  memcpy(&ctr[1], nonce, 12);
  ctr[15] = 1;
  uint8_t si[16];
  for (uint32_t b = 0; b < 8; b++) {
    uint32_t blk_cnt = b + 1;
    ctr[13] = (blk_cnt >> 16) & 0xFF;
    ctr[14] = (blk_cnt >> 8) & 0xFF;
    ctr[15] = blk_cnt & 0xFF;
    aes_encrypt(ctr, si, round_keys, 256);
    for (int i = 0; i < 16; i++) {
      first_chunk[b * 16 + i] ^= si[i];
    }
  }

  ota_header_t hdr;
  memcpy(&hdr, first_chunk, sizeof(ota_header_t));

  uint32_t total_flash_bytes = 0x200 + hdr.image_size;
  uint32_t sectors_to_erase = 1;
  if (total_flash_bytes > SECTOR4_SIZE) sectors_to_erase = 2;
  if (total_flash_bytes > SECTOR4_SIZE + SECTOR567_SIZE) sectors_to_erase = 3;
  if (total_flash_bytes > SECTOR4_SIZE + 2 * SECTOR567_SIZE) sectors_to_erase = 4;
  HAL_FLASH_Unlock();
  __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | 
                         FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);
  IWDG->KR = IWDG_KEY_RELOAD;
  FLASH_EraseInitTypeDef EraseInitStruct = {
    .TypeErase    = FLASH_TYPEERASE_SECTORS,
    .VoltageRange = FLASH_VOLTAGE_RANGE_3,
    .Sector       = FLASH_SECTOR_4,
    .NbSectors    = sectors_to_erase
  };
  uint32_t SectorError;
  if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK) {
    HAL_FLASH_Lock();
    printf("[FLASH ERROR] Erase failed!\r\n");
    return 0;
  }

  //Decrypt and install
  uint32_t plaintext_len = sizeof(ota_header_t) + hdr.image_size;
  uint32_t remaining = plaintext_len;
  uint32_t src_addr = ext_slot_addr + 28;
  uint32_t block_counter = 1;
  uint32_t total_written = 0;
  uint8_t chunk[256];
  while (remaining > 0) {
    IWDG->KR = IWDG_KEY_RELOAD;
    uint16_t chunk_len = (remaining > sizeof(chunk)) ? sizeof(chunk) : (uint16_t)remaining;
    W25Q64_ReadData(src_addr, chunk, chunk_len);

    //Decrypt
    for (uint16_t offset = 0; offset < chunk_len; offset += 16) {
      uint16_t blk_len = (chunk_len - offset > 16) ? 16 : (chunk_len - offset);
      ctr[13] = (block_counter >> 16) & 0xFF;
      ctr[14] = (block_counter >> 8) & 0xFF;
      ctr[15] = block_counter & 0xFF;
      block_counter++;
      aes_encrypt(ctr, si, round_keys, 256);
      for (int b = 0; b < blk_len; b++) chunk[offset + b] ^= si[b];
    }

    //Write internal Flash
     for (uint16_t i = 0; i < chunk_len; i += 4) {
      uint32_t current_plain_offset = total_written + i;
      uint32_t flash_dest;
      if (current_plain_offset < sizeof(ota_header_t)) {
        flash_dest = HEADER_START_ADDRESS + current_plain_offset;
      } else {
        flash_dest = APP_START_ADDRESS + (current_plain_offset - sizeof(ota_header_t));
      }
      uint32_t word_val = 0xFFFFFFFF;
      uint16_t copy_bytes = (chunk_len - i >= 4) ? 4 : (chunk_len - i);
      memcpy(&word_val, &chunk[i], copy_bytes);
      if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, flash_dest, word_val) != HAL_OK) {
        HAL_FLASH_Lock();
        printf("[FLASH ERROR] Program failed at 0x%08lX\r\n", (unsigned long)flash_dest);
        return 0;
      }
    }
    total_written += chunk_len;
    src_addr += chunk_len;
    remaining -= chunk_len;
  }
  HAL_FLASH_Lock();
  secure_memzero(round_keys, sizeof(round_keys));
  secure_memzero(device_key, sizeof(device_key));
  printf("[INSTALL] Firmware decrypted and flashed successfully!\r\n");
  return 1;
}

static void enter_recovery_mode(const char *reason)
{
  printf("[RECOVERY] %s. Waiting for new OTA package...\r\n", reason);
  while (1) {
    IWDG->KR = IWDG_KEY_RELOAD;
    int status = wait_for_ota_package();
    uint8_t current_slot = boot_get_slot();
    uint32_t new_slot_addr;
    

    if(current_slot == BOOT_SLOT_A){
      new_slot_addr = EXT_FLASH_SLOT_B_ADDR;
    }
    else if(current_slot == BOOT_SLOT_B){
      new_slot_addr = EXT_FLASH_SLOT_A_ADDR; 
    }
    else{
      // Initial install
      boot_set_slot(BOOT_SLOT_A);
      new_slot_addr = EXT_FLASH_SLOT_B_ADDR;
    }

    if (status == OTA_STATUS_OK) {
      if (verify_encrypted_staging(new_slot_addr,1) &&
          install_firmware(new_slot_addr) &&
          verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
        watchdog_clear_boot_fail_count();
        boot_set_state(BOOT_STATE_TESTING);
        printf("[RECOVERY] Update installed! Rebooting system...\r\n");
        HAL_Delay(100);
        NVIC_SystemReset();
      }
      else {
        printf("[RECOVERY] Firmware verification/install failed! Waiting again...\r\n");
      }
    }
  }
}

int backup_firmware(uint32_t ext_backup_addr){
  /*
  0.이미 검증된 상태 => 헤더 매직/크기 검증
  1.w25q64 메모리 삭제
  2.앱 읽어오기
  3.w25q64에 쓰기
  4.w25q64 검증
  5.return 하기
  */
  
  //w25q64 메모리 삭제
  ota_header_t hdr;
  read_internal_memory(HEADER_START_ADDRESS, (uint8_t *)&hdr, sizeof(ota_header_t));
  if (!validate_ota_header(&hdr)) {
    return 0;
  }

  uint32_t total_bytes = sizeof(ota_header_t) + hdr.image_size;
  uint32_t sectors_needed = (total_bytes + 4095) / 4096;
  for (uint32_t i = 0; i < sectors_needed; i++) {
    IWDG->KR = IWDG_KEY_RELOAD;
    if (!W25Q64_EraseSector(ext_backup_addr + i * 0x1000))
      return 0;
  }

  //앱 읽고 쓰기
  uint8_t buffer[256];
  uint32_t dst_addr = ext_backup_addr;
  uint32_t src_addr = APP_START_ADDRESS;
  uint32_t read_size = 256;
  uint32_t remaining = hdr.image_size;

  //헤더 쓰기
  if(!W25Q64_WriteStream(dst_addr, (uint8_t *)&hdr, sizeof(ota_header_t)))
      return 0;
  
  dst_addr += sizeof(ota_header_t);

  while(remaining > 0){
    IWDG->KR = IWDG_KEY_RELOAD;
    if(remaining >= 256)
      read_size = 256;
    else
      read_size = remaining;
    read_internal_memory(src_addr, buffer, read_size);
    if(!W25Q64_WriteStream(dst_addr, buffer, read_size))
      return 0;
    remaining -= read_size;
    dst_addr += read_size;
    src_addr += read_size;
  }
  if (!verify_firmware_common(ext_backup_addr, 
                            ext_backup_addr + sizeof(ota_header_t), 
                            read_external_flash, 
                            0)) {
    return 0;
  }
  return 1;
}

void boot_set_state(uint32_t state){
  __HAL_RCC_PWR_CLK_ENABLE();
  PWR->CR |= PWR_CR_DBP;
  RTC->BKP1R = state;
  PWR->CR &= ~PWR_CR_DBP;
}

uint32_t boot_get_state(void){
  return RTC->BKP1R;
}

void boot_set_slot(uint8_t slot){
  __HAL_RCC_PWR_CLK_ENABLE();
  PWR->CR |= PWR_CR_DBP;
  RTC->BKP2R = slot;
  PWR->CR &= ~PWR_CR_DBP;
}

uint8_t boot_get_slot(void){
  return RTC->BKP2R;
}

void bootloader_run(void)
{
  int bootloop_detected = 0;
  int was_iwdg_reset = watchdog_was_reset_by_iwdg();
  uint8_t current_slot = boot_get_slot();
  uint32_t current_slot_addr;
  uint32_t new_slot_addr;
    

  if(current_slot == BOOT_SLOT_A){
    current_slot_addr = EXT_FLASH_SLOT_A_ADDR;
    new_slot_addr = EXT_FLASH_SLOT_B_ADDR;
  }
  else if(current_slot == BOOT_SLOT_B){
    current_slot_addr = EXT_FLASH_SLOT_B_ADDR;
    new_slot_addr = EXT_FLASH_SLOT_A_ADDR ;
  }
  else{
    // Initial install    
    boot_set_slot(BOOT_SLOT_A);
    current_slot_addr = EXT_FLASH_SLOT_A_ADDR;
    new_slot_addr = EXT_FLASH_SLOT_B_ADDR;
  }

  if (was_iwdg_reset) {
    uint32_t fail_count = watchdog_get_boot_fail_count() + 1;
    watchdog_set_boot_fail_count(fail_count);
    printf("[WARNING] System rebooted due to IWDG WATCHDOG TIMEOUT! (Fail count: %lu)\r\n", (unsigned long)fail_count);
    if (fail_count >= 3) {
      bootloop_detected = 1;
      printf("[SECURITY] Bootloop detected! Watchdog failed %lu times consecutively. Rollback firmware.\r\n", (unsigned long)fail_count);
      if (boot_get_state() == BOOT_STATE_TESTING){
        if(verify_encrypted_staging(current_slot_addr,0)){
                        if(install_firmware(current_slot_addr)){
                        printf("[BOOT] Rollback complted successfully!\r\n");
                        boot_set_state(BOOT_STATE_NORMAL);  // 정상 상태로 원복!
                        watchdog_clear_boot_fail_count();  
                        HAL_Delay(100);
                        NVIC_SystemReset();
          }
        }
      }
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
      uint8_t active_slot = boot_get_slot();
      new_slot_addr = (active_slot == BOOT_SLOT_B) ? EXT_FLASH_SLOT_A_ADDR : EXT_FLASH_SLOT_B_ADDR;

      
      if(verify_encrypted_staging(new_slot_addr,1)){
        // Add Install new firmware
        if(install_firmware(new_slot_addr)){
          printf("[BOOT] New firmware installed successfully!\r\n");
          if (verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
            boot_set_state(BOOT_STATE_TESTING);
            printf("[BOOT] Update success! Rebooting...\r\n");
            watchdog_clear_boot_fail_count();
            HAL_Delay(100);
            NVIC_SystemReset();
          }
          else{
            printf("[BOOT] Update failed! Roolback previous firmware\r\n");
            //rollback code
            if(verify_encrypted_staging(current_slot_addr, 0)){
              if(install_firmware(current_slot_addr)){
                printf("[BOOT] Rollback complted successfully!\r\n");
                boot_set_state(BOOT_STATE_NORMAL);
                watchdog_clear_boot_fail_count();
                HAL_Delay(100);
                NVIC_SystemReset();
              }
            }
          }
        }
        else{
          printf("[BOOT] Update failed! Roolback previous firmware\r\n");
            //rollback code
          if(verify_encrypted_staging(current_slot_addr,0)){
              if(install_firmware(current_slot_addr)){
              printf("[BOOT] Rollback complted successfully!\r\n");
              HAL_Delay(100);
              watchdog_clear_boot_fail_count();
              boot_set_state(BOOT_STATE_NORMAL);
              NVIC_SystemReset();
            }
          }
        }
      }
      else{
        printf("[BOOT] OTA package verification failed! Staying in bootloader.\r\n");
      }
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
