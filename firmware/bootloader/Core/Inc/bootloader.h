/**
  ******************************************************************************
  * @file           : bootloader.h
  * @brief          : Header for Secure Bootloader operations and verification
  ******************************************************************************
  */

#ifndef __BOOTLOADER_H
#define __BOOTLOADER_H

#include "main.h"
#include "boot_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Pack structures to 1-byte alignment
#pragma pack(push, 1)
typedef struct {
  uint32_t magic;               // 4 bytes: "OTAF"
  uint16_t format_version;      // 2 bytes: Format version
  uint16_t header_size;         // 2 bytes: 120
  uint32_t target_id;           // 4 bytes: Target device ID (ex: 0x0411)
  uint32_t image_version;       // 4 bytes: Image version
  uint32_t image_size;          // 4 bytes: Size of the image payload
  uint8_t hash_alg;             // 1 byte: Hash algorithm (0x01 for SHA-256)
  uint8_t sig_alg;              // 1 byte: Signature algorithm (0x01 for ECDSA P-256)
  uint8_t reserved[2];          // 2 bytes: 0x00, 0x00
  uint8_t payload_sha256[32];   // 32 bytes: SHA-256 hash of the image payload
  uint8_t signature[64];        // 64 bytes: ECDSA signature (r 32 + s 32)
} ota_header_t;
#pragma pack(pop)

/**
 * @brief  Verify the OTA header structure and its fields.
 * @retval 1: Valid, 0: Error
 */
int validate_ota_header(const ota_header_t *header);

/**
 * @brief  Verify the stored firmware in internal flash (header and app binary)
 * @retval 1: Valid, 0: Error
 */
int verify_stored_firmware(uint32_t header_address, uint32_t app_address);

/**
 * @brief  Verify staged firmware in external flash
 * @retval 1: Valid, 0: Error
 */
int verify_staging_firmware(uint32_t ext_header_address);

/**
 * @brief  Jump to the application at the specified address.
 * @param  app_address: Start address of the application binary
 */
void jump_to_application(uint32_t app_address);

/**
 * @brief  Main bootloader logic routine:
 *         Checks user button, enters OTA mode if pressed or if firmware invalid,
 *         otherwise verifies and jumps to the application.
 */
void bootloader_run(void);

#ifdef __cplusplus
}
#endif

#endif /* __BOOTLOADER_H */

