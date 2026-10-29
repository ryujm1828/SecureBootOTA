/**
  ******************************************************************************
  * @file           : ota_manager.h
  * @brief          : OTA Protocol Handler and Firmware Installation
  ******************************************************************************
  */

#ifndef __OTA_MANAGER_H
#define __OTA_MANAGER_H

#include "main.h"
#include "boot_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Send 1-byte ACK/NAK response over UART
 * @param  res: ACK (0x06) or NAK (0x15)
 */
void send_response(uint8_t res);

/**
 * @brief  Decrypt AES-CCM encrypted package from external flash and verify MAC tag.
 * @param  enc_addr: Address in external flash where encrypted package is stored
 * @param  dec_addr: Address in external flash where decrypted plaintext will be written
 * @param  total_enc_len: Length of the encrypted package (Nonce + MAC + Ciphertext)
 * @param  key: 256-bit (32 bytes) AES key
 * @retval 1: Success, 0: Error or MAC mismatch
 */
int decrypt_ota_package(uint32_t enc_addr, uint32_t dec_addr, uint32_t total_enc_len, const uint8_t key[32]);

/**
 * @brief  Decrypt staging package, verify firmware, and install to internal flash.
 * @param  enc_addr: Address in external flash where encrypted package is stored
 * @param  dec_addr: Address in external flash where decrypted plaintext will be written
 * @param  enc_size: Size of the encrypted package
 * @param  key: 256-bit AES key
 * @retval 1: Success, 0: Error
 */
int decrypt_and_install_firmware(uint32_t enc_addr, uint32_t dec_addr, uint32_t enc_size, const uint8_t key[32]);

/**
 * @brief  Wait for and receive OTA update package from UART, then decrypt, verify, and install.
 * @retval OTA_STATUS_OK on success, OTA_STATUS_TIMEOUT on timeout, OTA_STATUS_ERROR on failure.
 */
int wait_for_ota_package(void);

#ifdef __cplusplus
}
#endif

#endif /* __OTA_MANAGER_H */

