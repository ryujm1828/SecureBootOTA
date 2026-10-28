/**
  ******************************************************************************
  * @file           : boot_config.h
  * @brief          : Configuration, memory map, and constants for Secure Bootloader
  ******************************************************************************
  */

#ifndef __BOOT_CONFIG_H
#define __BOOT_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* Security Tokens                                                            */
/* ========================================================================== */
#define SEC_TRUE   0x5A5A5A5AU
#define SEC_FALSE  0xA5A5A5A5U

/* ========================================================================== */
/* Internal Flash Memory Map                                                  */
/* ========================================================================== */
#define HEADER_START_ADDRESS 0x08010000
#define APP_START_ADDRESS    0x08010200
#define MAX_APP_BINARY_SIZE  (0x70000 - 0x200) // Sector 4~7 (448KB) - Header (512B)

/* ========================================================================== */
/* External Flash (W25Q64) Memory Map                                         */
/* ========================================================================== */
#define EXT_FLASH_ENC_ADDR   0x000000 // Encrypted OTA package received via UART
#define EXT_FLASH_DEC_ADDR   0x100000 // Decrypted OTA package (1MB offset)

/* ========================================================================== */
/* Expected OTA Header Constants                                              */
/* ========================================================================== */
#define EXPECTED_MAGIC ( (uint32_t)'O' | ((uint32_t)'T' << 8) | ((uint32_t)'A' << 16) | ((uint32_t)'F' << 24) )
#define EXPECTED_FORMAT_VERSION 0x0001
#define EXPECTED_HEADER_SIZE 120
#define EXPECTED_TARGET_ID 0x0411

/* ========================================================================== */
/* Device Unique ID (UID) Settings                                            */
/* ========================================================================== */
#define STM32_UID_BASE 0x1FFF7A10

// Set to 1 to use real hardware UID from STM32 registers (0x1FFF7A10)
// Set to 0 to use sample UID matching host/ota_encrypt.py (0x00112233445566778899AABB)
#define USE_REAL_DEVICE_UID  0

/* ========================================================================== */
/* OTA Protocol Constants                                                     */
/* ========================================================================== */
#define FRAME_MAGIC 0xABCD
#define CMD_HELLO   1
#define CMD_BEGIN   2
#define CMD_DATA    3
#define CMD_END     4
#define ACK         0x06
#define NAK         0x15

/* ========================================================================== */
/* Cryptographic Keys & Lengths (Definitions in boot_keys.c)                  */
/* ========================================================================== */
#define MASTER_KEY_LEN 32
#define OTA_SALT_LEN   8

extern const uint8_t ecdsa_public_key[64];
extern const uint8_t MASTER_KEY[33];
extern const uint8_t OTA_SALT[9];

#ifdef __cplusplus
}
#endif

#endif /* __BOOT_CONFIG_H */

