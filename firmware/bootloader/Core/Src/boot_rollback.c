/**
  ******************************************************************************
  * @file           : boot_rollback.c
  * @brief          : Firmware backup, rollback, and boot metadata implementation
  ******************************************************************************
  */

#include "boot_rollback.h"
#include "bootloader.h"
#include "boot_watchdog.h"
#include "w25q64.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief  Read boot metadata from external flash. Initialize defaults if invalid.
 */
int boot_meta_read(boot_meta_t *meta)
{
    W25Q64_ReadData(EXT_FLASH_META_ADDR, (uint8_t *)meta, sizeof(boot_meta_t));
    if (meta->magic != BOOT_META_MAGIC) {
        // Initialize default metadata when missing or unformatted
        memset(meta, 0, sizeof(boot_meta_t));
        meta->magic = BOOT_META_MAGIC;
        meta->state = BOOT_STATE_NORMAL;
        meta->backup_valid = 0;
        meta->backup_size = 0;
        meta->rollback_count = 0;
        return 0;
    }
    return 1;
}

/**
 * @brief  Save boot metadata to external flash.
 */
int boot_meta_write(const boot_meta_t *meta)
{
    W25Q64_EraseSector(EXT_FLASH_META_ADDR);
    W25Q64_WriteStream(EXT_FLASH_META_ADDR, (uint8_t *)meta, sizeof(boot_meta_t));
    return 1;
}

/**
 * @brief  Backup current internal flash firmware to external flash backup slot.
 */
int backup_current_firmware(void)
{
    const ota_header_t *hdr = (const ota_header_t *)HEADER_START_ADDRESS;

    // Verify current running firmware integrity before backing up
    if (!verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
        printf("[BACKUP] No valid firmware found in internal flash to backup.\r\n");
        return 0;
    }

    uint32_t total_backup_size = sizeof(ota_header_t) + hdr->image_size;
    printf("[BACKUP] Backing up current firmware (Size: %lu bytes) to External Flash 0x%06X...\r\n", 
           (unsigned long)total_backup_size, EXT_FLASH_BKUP_ADDR);

    // 1. Erase external flash backup sectors
    uint32_t sectors_needed = (total_backup_size + 4095) / 4096;
    for (uint32_t i = 0; i < sectors_needed; i++) {
        W25Q64_EraseSector(EXT_FLASH_BKUP_ADDR + i * 0x1000);
    }

    // 2. Copy header and application binary to external flash
    uint8_t buffer[256];
    uint32_t src_addr = HEADER_START_ADDRESS;
    uint32_t dst_addr = EXT_FLASH_BKUP_ADDR;
    uint32_t remaining = total_backup_size;

    while (remaining > 0) {
        uint16_t chunk = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
        memcpy(buffer, (const void *)src_addr, chunk);
        W25Q64_WriteStream(dst_addr, buffer, chunk);

        src_addr += chunk;
        dst_addr += chunk;
        remaining -= chunk;
    }

    // 3. Verify backup copy integrity (ECDSA signature and SHA-256 payload hash)
    if (!verify_staging_firmware(EXT_FLASH_BKUP_ADDR)) {
        printf("[BACKUP ERROR] Backup firmware verification failed!\r\n");
        return 0;
    }

    // 4. Update metadata to mark backup as valid
    boot_meta_t meta;
    boot_meta_read(&meta);
    meta.backup_valid = 1;
    meta.backup_size = total_backup_size;
    boot_meta_write(&meta);

    printf("[BACKUP] Backup completed and verified successfully!\r\n");
    return 1;
}

/**
 * @brief  Restore backup firmware from external flash to internal flash.
 */
int rollback_to_backup_firmware(void)
{
    printf("\r\n==================================================\r\n");
    printf("[ROLLBACK] Initiating Automatic Firmware Rollback!\r\n");
    printf("==================================================\r\n");

    boot_meta_t meta;
    boot_meta_read(&meta);

    if (!meta.backup_valid) {
        printf("[ROLLBACK ERROR] No valid backup available in External Flash!\r\n");
        return 0;
    }

    // 1. Verify backup image signature and hash before restoring
    if (!verify_staging_firmware(EXT_FLASH_BKUP_ADDR)) {
        printf("[ROLLBACK ERROR] Backup image is corrupted or invalid!\r\n");
        return 0;
    }

    // 2. Erase internal application flash sectors (Sector 4 ~ 7)
    printf("[ROLLBACK] Erasing internal flash...\r\n");
    HAL_FLASH_Unlock();
    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | 
                           FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

    FLASH_EraseInitTypeDef EraseInitStruct;
    uint32_t SectorError;
    EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
    EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    EraseInitStruct.Sector = FLASH_SECTOR_4;
    EraseInitStruct.NbSectors = 4;
    if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK) {
        HAL_FLASH_Lock();
        printf("[ROLLBACK ERROR] Internal flash erase failed!\r\n");
        return 0;
    }

    // 3. Program backup firmware into internal flash starting at header address
    printf("[ROLLBACK] Restoring backup firmware to internal flash...\r\n");
    uint32_t src_addr = EXT_FLASH_BKUP_ADDR;
    uint32_t dst_addr = HEADER_START_ADDRESS;
    uint32_t remaining = meta.backup_size;
    uint8_t buffer[256];

    while (remaining > 0) {
        uint16_t chunk = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
        W25Q64_ReadData(src_addr, buffer, chunk);
        for (uint16_t i = 0; i < chunk; i++) {
            HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, dst_addr++, buffer[i]);
        }
        src_addr += chunk;
        remaining -= chunk;
    }
    HAL_FLASH_Lock();

    // 4. Verify restored firmware in internal flash
    if (!verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
        printf("[ROLLBACK ERROR] Verification failed after restoring backup!\r\n");
        return 0;
    }

    // 5. Update metadata back to NORMAL state
    meta.state = BOOT_STATE_NORMAL;
    meta.rollback_count++;
    boot_meta_write(&meta);

    printf("[ROLLBACK SUCCESS] Firmware successfully restored to previous version!\r\n");
    return 1;
}

/**
 * @brief  Check boot state, confirm tokens, and watchdog reset flag; initiate rollback if needed.
 */
int check_and_handle_rollback(void)
{
    boot_meta_t meta;
    boot_meta_read(&meta);

    // Check if App confirmed successful boot via RTC backup register
    if (RTC->BKP0R == BOOT_CONFIRM_KEY) {
        RCC->APB1ENR |= RCC_APB1ENR_PWREN;
        PWR->CR |= PWR_CR_DBP;
        RTC->BKP0R = 0; // Clear confirm token

        if (meta.state == BOOT_STATE_TRIAL) {
            meta.state = BOOT_STATE_NORMAL;
            boot_meta_write(&meta);
            printf("[BOOT] App healthy! Firmware state promoted to NORMAL.\r\n");
        }
    }

    int is_iwdg = watchdog_was_reset_by_iwdg();

    // If new firmware was in TRIAL state and crashed/timed out
    if (meta.state == BOOT_STATE_TRIAL && is_iwdg) {
        printf("[ROLLBACK] Detected TRIAL firmware failure (IWDG reset). Initiating rollback...\r\n");
        if (rollback_to_backup_firmware()) {
            return 1;
        } else {
            printf("[ROLLBACK CRITICAL] Rollback failed. Entering recovery mode.\r\n");
            return -1;
        }
    }

    return 0;
}
