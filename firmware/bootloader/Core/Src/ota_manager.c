/**
  ******************************************************************************
  * @file           : ota_manager.c
  * @brief          : OTA Protocol Handler, Decryption, and Installation Implementation
  ******************************************************************************
  */

#include "ota_manager.h"
#include "bootloader.h"
#include "secure_utils.h"
#include "w25q64.h"
#include "aes.h"
#include "hkdf.h"
#include "boot_watchdog.h"
#include <stdio.h>
#include <string.h>

extern UART_HandleTypeDef huart2;

void send_response(uint8_t res)
{
  HAL_UART_Transmit(&huart2, &res, 1, 100);
}

/**
 * @brief  Decrypt AES-CCM encrypted package from external flash and verify MAC tag.
 * @retval 1: Success, 0: Error or MAC mismatch
 */
int decrypt_ota_package(uint32_t enc_addr, uint32_t dec_addr, uint32_t total_enc_len, const uint8_t key[32])
{
  if (total_enc_len <= 28) {
    printf("[OTA ERROR] Encrypted package too small: %lu bytes\r\n", (unsigned long)total_enc_len);
    return 0;
  }

  uint32_t plaintext_len = total_enc_len - 28;

  // Read Nonce (12 bytes) and MAC Tag (16 bytes) from external flash
  uint8_t nonce[12];
  uint8_t rx_mac[16];
  W25Q64_ReadData(enc_addr, nonce, 12);
  W25Q64_ReadData(enc_addr + 12, rx_mac, 16);

  // Set up AES round keys (256-bit key)
  WORD round_keys[60];
  aes_key_setup(key, round_keys, 256);

  // Compute S_0 = AES_Encrypt(Ctr_0) for MAC masking
  uint8_t ctr[16];
  memset(ctr, 0, sizeof(ctr));
  ctr[0] = 0x02; // Flags: q - 1 = 3 - 1 = 2 (for 12-byte nonce)
  memcpy(&ctr[1], nonce, 12);
  uint8_t s0[16];
  aes_encrypt(ctr, s0, round_keys, 256);

  // Initialize CBC-MAC state Y_0 = AES_Encrypt(B_0)
  uint8_t b0[16];
  memset(b0, 0, sizeof(b0));
  b0[0] = 0x3A; // Flags: Adata=0, (M-2)/2=7 (16-byte MAC), q-1=2
  memcpy(&b0[1], nonce, 12);
  b0[13] = (plaintext_len >> 16) & 0xFF;
  b0[14] = (plaintext_len >> 8) & 0xFF;
  b0[15] = plaintext_len & 0xFF;

  uint8_t y[16];
  aes_encrypt(b0, y, round_keys, 256);

  // Erase sectors in external flash for decrypted plaintext
  uint32_t sectors_needed = (plaintext_len + 4095) / 4096;
  for (uint32_t i = 0; i < sectors_needed; i++) {
    W25Q64_EraseSector(dec_addr + i * 0x1000);
    IWDG->KR = IWDG_KEY_RELOAD;
  }

  // Decrypt ciphertext and compute CBC-MAC in 256-byte chunks
  uint32_t remaining = plaintext_len;
  uint32_t src_ct_addr = enc_addr + 28;
  uint32_t dst_pt_addr = dec_addr;
  uint32_t block_counter = 1;
  uint8_t chunk[256];

  while (remaining > 0) {
    uint16_t chunk_len = (remaining > sizeof(chunk)) ? sizeof(chunk) : (uint16_t)remaining;
    W25Q64_ReadData(src_ct_addr, chunk, chunk_len);

    for (uint16_t offset = 0; offset < chunk_len; offset += 16) {
      uint16_t blk_len = (chunk_len - offset > 16) ? 16 : (chunk_len - offset);

      // Prepare Ctr_i
      ctr[13] = (block_counter >> 16) & 0xFF;
      ctr[14] = (block_counter >> 8) & 0xFF;
      ctr[15] = block_counter & 0xFF;
      block_counter++;

      uint8_t si[16];
      aes_encrypt(ctr, si, round_keys, 256);

      // Decrypt CTR block: Plaintext = Ciphertext ^ S_i
      for (int b = 0; b < blk_len; b++) {
        chunk[offset + b] ^= si[b];
      }

      // Update CBC-MAC with plaintext: Y_i = AES_Encrypt(Y_{i-1} ^ P_i)
      uint8_t mac_in[16] = {0};
      memcpy(mac_in, &chunk[offset], blk_len);
      for (int b = 0; b < 16; b++) {
        y[b] ^= mac_in[b];
      }
      aes_encrypt(y, y, round_keys, 256);
    }

    // Write decrypted plaintext to external flash
    W25Q64_WriteStream(dst_pt_addr, chunk, chunk_len);

    src_ct_addr += chunk_len;
    dst_pt_addr += chunk_len;
    remaining -= chunk_len;
  }

  // Finalize MAC: Calculated_MAC = Y_m ^ S_0
  uint8_t calculated_mac[16];
  for (int i = 0; i < 16; i++) {
    calculated_mac[i] = y[i] ^ s0[i];
  }

  // Constant-time MAC comparison
  int mac_match = (constant_time_memcmp(calculated_mac, rx_mac, 16) == 0);

  // Clear sensitive keys and cipher states from RAM
  secure_memzero(round_keys, sizeof(round_keys));
  secure_memzero(s0, sizeof(s0));
  secure_memzero(y, sizeof(y));
  secure_memzero(ctr, sizeof(ctr));
  secure_memzero(calculated_mac, sizeof(calculated_mac));

  // Verify MAC authentication tag
  if (!mac_match) {
    for (uint32_t i = 0; i < sectors_needed; i++)
        W25Q64_EraseSector(dec_addr + i * 0x1000);
    return 0;
  }

  printf("[SECURITY] AES-CCM Decryption and Authentication Successful! (%lu bytes)\r\n",
         (unsigned long)plaintext_len);
  return 1;
}

int wait_for_ota_package(void)
{
  uint8_t header[8];
  uint8_t payload[256];
  uint8_t checksum;

  uint32_t expected_seq = 0;
  uint32_t total_received = 0;
  uint32_t ext_flash_addr = EXT_FLASH_ENC_ADDR;

  uint8_t transfer_started = 0;
  uint32_t session_start = HAL_GetTick();
  uint32_t last_activity_tick = session_start;
  uint32_t expected_total_size = 0;

  printf("\r\n[OTA] Waiting for OTA update from PC (Timeout: 30s)...\r\n");

  while (1) {
    IWDG->KR = IWDG_KEY_RELOAD;
    // Check timeout: 30s before CMD_BEGIN, 10s between packets during transfer
    if (!transfer_started) {
      if ((HAL_GetTick() - session_start) >= OTA_WAIT_TIMEOUT_MS) {
        printf("[OTA] Timeout: No CMD_BEGIN received within 30 seconds. Exiting OTA mode...\r\n");
        return OTA_STATUS_TIMEOUT;
      }
    } else {
      if ((HAL_GetTick() - last_activity_tick) >= OTA_PACKET_TIMEOUT_MS) {
        printf("[OTA ERROR] Packet reception timeout (10s). Aborting OTA session.\r\n");
        return OTA_STATUS_ERROR;
      }
    }

    // Clear overrun or error flags to ensure reliable reception
    __HAL_UART_CLEAR_OREFLAG(&huart2);

    uint8_t b;
    if (HAL_UART_Receive(&huart2, &b, 1, 100) != HAL_OK) continue;
    if (b != (FRAME_MAGIC & 0xFF)) continue;

    if (HAL_UART_Receive(&huart2, &b, 1, 100) != HAL_OK) continue;
    if (b != ((FRAME_MAGIC >> 8) & 0xFF)) continue;

    header[0] = (uint8_t)(FRAME_MAGIC & 0xFF);
    header[1] = (uint8_t)((FRAME_MAGIC >> 8) & 0xFF);
    if (HAL_UART_Receive(&huart2, &header[2], 6, 1000) != HAL_OK) continue;

    uint8_t version = header[2];
    uint8_t cmd = header[3];
    uint16_t seq = header[4] | (header[5] << 8);
    uint16_t length = header[6] | (header[7] << 8);
    (void)version;

    if (length > sizeof(payload)) {
      send_response(NAK);
      continue;
    }

    if (length > 0) {
      if (HAL_UART_Receive(&huart2, payload, length, 1000) != HAL_OK) {
        send_response(NAK);
        continue;
      }
    }

    if (HAL_UART_Receive(&huart2, &checksum, 1, 1000) != HAL_OK) {
      send_response(NAK);
      continue;
    }
    
    uint8_t calculated_checksum = 0;
    for (int i = 0; i < 8; i++) calculated_checksum += header[i];
    for (int i = 0; i < length; i++) calculated_checksum += payload[i];
    if (calculated_checksum != checksum) {
      send_response(NAK);
      continue;
    }

    if (cmd == CMD_HELLO) {
      send_response(ACK);
    }
    else if (cmd == CMD_BEGIN) {
      if (length < 4) {
        send_response(NAK);
        continue;
      }
      expected_total_size = (uint32_t)payload[0] |
                          ((uint32_t)payload[1] << 8) |
                          ((uint32_t)payload[2] << 16) |
                          ((uint32_t)payload[3] << 24);
      uint32_t max_allowed_pkg = 28 + sizeof(ota_header_t) + MAX_APP_BINARY_SIZE;
      if (expected_total_size <= 28 || expected_total_size > max_allowed_pkg) {
        printf("[OTA ERROR] Invalid package size: %lu bytes (Max: %lu)\r\n", 
              (unsigned long)expected_total_size, (unsigned long)max_allowed_pkg);
        send_response(NAK);
        continue;
      }
      
      expected_seq = 0;
      total_received = 0;
      ext_flash_addr = EXT_FLASH_ENC_ADDR;
      transfer_started = 1;
      last_activity_tick = HAL_GetTick();
      send_response(ACK);
    }
    else if (cmd == CMD_DATA) {
      last_activity_tick = HAL_GetTick();
      //Erase sector if starting a new 4KB block
      if (transfer_started && seq == expected_seq) {

        if ((ext_flash_addr % 0x1000) == 0) {
          if (!W25Q64_EraseSector(ext_flash_addr)) {
            printf("[OTA ERROR] External Flash erase failed at 0x%08lX\r\n", (unsigned long)ext_flash_addr);
            send_response(NAK);
            continue;
          }
        }

        if (!W25Q64_WriteStream(ext_flash_addr, payload, length)) {
          printf("[OTA ERROR] External Flash write failed at 0x%08lX\r\n", (unsigned long)ext_flash_addr);
          send_response(NAK);
          continue;
        }
        ext_flash_addr += length;
        total_received += length;
        expected_seq++;
        send_response(ACK);
    } else if(transfer_started && expected_seq > 0 && seq == (expected_seq - 1)) {
        send_response(ACK);
      } 
      else {
        send_response(NAK);
      } 
    }
    else if (cmd == CMD_END) {
      last_activity_tick = HAL_GetTick();
      if (expected_total_size != 0 && total_received != expected_total_size) {
        printf("[OTA ERROR] Package size mismatch! Expected: %lu, Received: %lu\r\n",
              (unsigned long)expected_total_size, (unsigned long)total_received);
        send_response(NAK);
        transfer_started = 0;
        session_start = HAL_GetTick();
        continue;
      }
      uint8_t device_uid[12];
#if USE_REAL_DEVICE_UID
      // Read 96-bit Unique ID from STM32 factory registers
      memcpy(device_uid, (const void *)STM32_UID_BASE, 12);
#else
      // Sample UID matching host/ota_encrypt.py (0x00112233445566778899AABB)
      const uint8_t sample_uid[12] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(device_uid, sample_uid, 12);
#endif

      // Derive device-specific AES key using HKDF-SHA256
      uint8_t device_aes_key[32];
      hkdf_sha256(OTA_SALT, OTA_SALT_LEN,
                  MASTER_KEY, MASTER_KEY_LEN,
                  device_uid, 12,
                  device_aes_key, 32);

      // Decrypt staging package, verify it, and install to internal flash
      int dec_ok = decrypt_ota_package(EXT_FLASH_ENC_ADDR, EXT_FLASH_DEC_ADDR, total_received, device_aes_key);
      
      // Wipe derived device key and UID from RAM
      secure_memzero(device_aes_key, sizeof(device_aes_key));
      secure_memzero(device_uid, sizeof(device_uid));

      if (dec_ok) {
        send_response(ACK);
        printf("[OTA] Firmware package decrypted successfully.\r\n");
        HAL_Delay(100);
        return OTA_STATUS_OK;
      } else {
        send_response(NAK);
        printf("[OTA ERROR] Decryption, verification, or installation failed!\r\n");
        transfer_started = 0;
        expected_seq = 0;
        total_received = 0;
        session_start = HAL_GetTick();
      }
    }
  }
}
