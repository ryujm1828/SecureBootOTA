/**
  ******************************************************************************
  * @file           : boot_rollback.h
  * @brief          : Firmware backup, rollback, and boot metadata declarations
  ******************************************************************************
  */

#ifndef __BOOT_ROLLBACK_H
#define __BOOT_ROLLBACK_H

#include "boot_config.h"
#include <stdint.h>

#define BOOT_META_MAGIC      0x4D455441U // "META"
#define BOOT_CONFIRM_KEY     0xA55A5AA5U // Token written by App in RTC Backup register

typedef enum {
    BOOT_STATE_NORMAL = 0, // Confirmed stable firmware
    BOOT_STATE_TRIAL  = 1  // Newly installed trial firmware awaiting confirmation
} boot_state_t;

typedef struct {
    uint32_t magic;          // Magic identifier (BOOT_META_MAGIC)
    uint32_t state;          // boot_state_t (NORMAL or TRIAL)
    uint32_t backup_valid;   // 1 if backup image in external flash is valid
    uint32_t backup_size;    // Size of backup image including header (bytes)
    uint32_t rollback_count; // Number of automatic rollbacks executed
    uint32_t reserved[3];    // Reserved for 32-byte alignment
} boot_meta_t;

/**
 * @brief  Read boot metadata from external flash.
 * @param  meta: Pointer to metadata destination buffer
 * @retval 1: Success, 0: Error or freshly initialized
 */
int boot_meta_read(boot_meta_t *meta);

/**
 * @brief  Save boot metadata to external flash.
 * @param  meta: Pointer to metadata structure to write
 * @retval 1: Success, 0: Error
 */
int boot_meta_write(const boot_meta_t *meta);

/**
 * @brief  Backup current internal flash firmware to external flash.
 * @retval 1: Success, 0: Error
 */
int backup_current_firmware(void);

/**
 * @brief  Restore backup firmware from external flash to internal flash.
 * @retval 1: Success, 0: Error
 */
int rollback_to_backup_firmware(void);

/**
 * @brief  Check boot state and watchdog reset flag; initiate rollback if needed.
 * @retval 1: Rollback executed, 0: No rollback needed, -1: Rollback failed
 */
int check_and_handle_rollback(void);

#endif /* __BOOT_ROLLBACK_H */
