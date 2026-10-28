/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "sha256.h"
#include "uECC.h"
#include "aes.h"
#include "hkdf.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
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

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
SPI_HandleTypeDef hspi1;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_SPI1_Init(void);
/* USER CODE BEGIN PFP */
void W25Q64_WaitForWriteEnd(void);
void W25Q64_WriteEnable(void);
void W25Q64_ReadData(uint32_t ReadAddr, uint8_t *pData, uint16_t read_size);
void W25Q64_EraseSector(uint32_t SectorAddr);
void W25Q64_WritePage(uint32_t PageAddr, uint8_t *pData, uint16_t write_size);
void W25Q64_WriteStream(uint32_t StartAddr, uint8_t *pData, uint16_t write_size);
int decrypt_ota_package(uint32_t enc_addr, uint32_t dec_addr, uint32_t total_enc_len, const uint8_t key[32]);
int decrypt_and_install_firmware(uint32_t enc_addr, uint32_t dec_addr, uint32_t enc_size, const uint8_t key[32]);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
#include <stdio.h>
#include <string.h>

// _write() function is used by printf() to send data over UART
int _write(int file, char *ptr, int len)
{
    HAL_UART_Transmit(&huart2, (uint8_t*)ptr, len, 1000);
    return len;
}
#define SEC_TRUE   0x5A5A5A5AU
#define SEC_FALSE  0xA5A5A5A5U

#define HEADER_START_ADDRESS 0x08010000
#define APP_START_ADDRESS    0x08010200
#define MAX_APP_BINARY_SIZE (0x70000 - 0x200) // Sector 4~7 (448KB) - Header (512B)
#define EXPECTED_MAGIC ( (uint32_t)'O' | ((uint32_t)'T' << 8) | ((uint32_t)'A' << 16) | ((uint32_t)'F' << 24) )
#define EXPECTED_FORMAT_VERSION 0x0001
#define EXPECTED_HEADER_SIZE 120
#define EXPECTED_TARGET_ID 0x0411

// ECDSA public key in C array format (NIST P-256)
const uint8_t ecdsa_public_key[64] = {
    0xf6, 0x6b, 0x60, 0x08, 0xf5, 0xf1, 0xa8, 0xab, 0x02, 0x04, 0xd5, 0x93, 0x8d, 0x55, 0x12, 0xe3,
    0x70, 0xdc, 0x6f, 0x7d, 0xeb, 0x53, 0x14, 0xaf, 0x6b, 0xbe, 0x07, 0x1f, 0x7e, 0x91, 0xf4, 0x0f,
    0x58, 0xd5, 0x42, 0xe4, 0x03, 0x92, 0xf7, 0x99, 0x43, 0xbd, 0x06, 0x68, 0x90, 0x65, 0x61, 0x77,
    0x68, 0x25, 0xa8, 0xdb, 0x58, 0x9f, 0x2d, 0xb3, 0x9d, 0x39, 0x57, 0xb7, 0x68, 0x37, 0x14, 0x6f
};

const uint8_t MASTER_KEY[] = "SecretCompanyMasterKey0123456789";
const uint8_t OTA_SALT[] = "OTA_SALT";

#define STM32_UID_BASE 0x1FFF7A10

// W25Q64 External Flash memory map for staged firmware
#define EXT_FLASH_ENC_ADDR   0x000000 // Encrypted OTA package received via UART
#define EXT_FLASH_DEC_ADDR   0x100000 // Decrypted OTA package (1MB offset)

// Device UID configuration:
// Set to 1 to use real hardware UID from STM32 registers (0x1FFF7A10)
// Set to 0 to use sample UID matching host/ota_encrypt.py (0x00112233445566778899AABB)
#define USE_REAL_DEVICE_UID  0

// OTA Protocol CONSTANTS
#define FRAME_MAGIC 0xABCD
#define CMD_HELLO 1
#define CMD_BEGIN 2
#define CMD_DATA 3
#define CMD_END 4
#define ACK 0x06
#define NAK 0x15

void send_response(uint8_t res){
  HAL_UART_Transmit(&huart2, &res, 1, 100);
}

// Secure memory wipe to prevent compiler dead-store optimization
static void secure_memzero(void *v, size_t n) {
  volatile uint8_t *p = (volatile uint8_t *)v;
  while (n--) {
    *p++ = 0;
  }
}

// Constant-time memory compare to prevent timing side-channel attacks
static int constant_time_memcmp(const void *a, const void *b, size_t len) {
  const uint8_t *p1 = (const uint8_t *)a;
  const uint8_t *p2 = (const uint8_t *)b;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (p1[i] ^ p2[i]);
  }
  return diff;
}

/**
 * @brief  Verify the OTA header structure and its fields.
 * @retval 1: Valid, 0: Error
 */
int validate_ota_header(const ota_header_t *header){
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
int verify_stored_firmware(uint32_t header_address, uint32_t app_address) {
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
  else{
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
  else{
    printf("[SECURITY] App SHA-256 Hash Mismatch! Firmware Rejected.\r\n");
    return 0;
  }
  if (sig_status == SEC_TRUE && flow_token == 0x33333333) {
    if (sig_status != SEC_FALSE) {
      printf("[SECURITY] Firmware verification successful! flow_token: 0x%08lX\r\n", (unsigned long)flow_token);
      return 1;
    }
  }
  else{
    printf("[SECURITY] Firmware verification failed! flow_token: 0x%08lX\r\n", (unsigned long)flow_token);
    return 0;
  }
  while(1) { __disable_irq(); }
  return 0;
}

int verify_staging_firmware(uint32_t ext_header_address){
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
  if(installed_hdr->magic == EXPECTED_MAGIC && hdr.image_version < installed_hdr->image_version) {
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
  else{
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
  else{
    printf("[OTA ERROR] App SHA-256 Hash Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  if (sig_status == SEC_TRUE && flow_token == 0x33333333) {
    if (sig_status != SEC_FALSE) {
        return 1;
    }
  }
  else{
    printf("[OTA ERROR] Staging firmware verification failed! flow_token: 0x%08lX\r\n", (unsigned long)flow_token);
    return 0;
  }
  
  while(1) { __disable_irq(); }
  
  return 0;
}

/**
 * @brief  Jump to the application at the specified address.
 */
void jump_to_application(uint32_t app_address) {
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
    printf("[SECURITY] AES-CCM MAC Verification Failed! Tag mismatch.\r\n");
    return 0;
  }

  printf("[SECURITY] AES-CCM Decryption and Authentication Successful! (%lu bytes)\r\n",
         (unsigned long)plaintext_len);
  return 1;
}

/**
 * @brief  Decrypt staging package, verify firmware, and install to internal flash.
 * @retval 1: Success, 0: Error
 */
int decrypt_and_install_firmware(uint32_t enc_addr, uint32_t dec_addr, uint32_t enc_size, const uint8_t key[32])
{
  // 1. Decrypt AES-CCM package from enc_addr into dec_addr
  if (!decrypt_ota_package(enc_addr, dec_addr, enc_size, key)) {
    return 0;
  }

  // 2. Verify decrypted staging firmware (Header, Anti-Rollback, Signature, Hash)
  if (!verify_staging_firmware(dec_addr)) {
    printf("[OTA ERROR] Decrypted firmware verification failed!\r\n");
    return 0;
  }

  printf("[BOARD] Decrypted firmware verified! Installing to Internal Flash...\r\n");

  // 3. Erase internal flash (Sector 4 ~ 7)
  HAL_FLASH_Unlock();
  __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | 
                         FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

  FLASH_EraseInitTypeDef EraseInitStruct;
  uint32_t SectorError;
  EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
  EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
  EraseInitStruct.Sector = FLASH_SECTOR_4; // Sector 4 ~ 7 (448KB)
  EraseInitStruct.NbSectors = 4;
  if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK) {
    HAL_FLASH_Lock();
    printf("[OTA ERROR] Internal flash erase failed!\r\n");
    return 0;
  }

  ota_header_t hdr;
  W25Q64_ReadData(dec_addr, (uint8_t *)&hdr, sizeof(ota_header_t));

  // 4. Copy Header to HEADER_START_ADDRESS (0x08010000)
  uint8_t *header_ptr = (uint8_t *)&hdr;
  for (uint32_t i = 0; i < sizeof(ota_header_t); i++) {
    HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, HEADER_START_ADDRESS + i, header_ptr[i]);
  }

  // 5. Copy App Binary to APP_START_ADDRESS (0x08010200)
  uint32_t src_app_addr = dec_addr + sizeof(ota_header_t);
  uint32_t dest_addr = APP_START_ADDRESS;
  uint32_t remaining = hdr.image_size;
  uint8_t buffer[256];

  while (remaining > 0) {
    uint16_t read_size = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
    W25Q64_ReadData(src_app_addr, buffer, read_size);
    for (uint16_t i = 0; i < read_size; i++) {
      HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, dest_addr++, buffer[i]);
    }
    src_app_addr += read_size;
    remaining -= read_size;
  }
  HAL_FLASH_Lock();

  // 6. Verify installed firmware in internal flash
  if (!verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
    printf("[OTA ERROR] Verification failed after flashing. Aborting.\r\n");
    return 0;
  }

  return 1;
}

void wait_for_ota_package(void){
  uint8_t header[8];
  uint8_t payload[256];
  uint8_t checksum;

  uint16_t expected_seq = 0;
  uint32_t total_received = 0;
  static uint32_t ext_flash_addr = EXT_FLASH_ENC_ADDR;

  printf("\r\n Waiting for OTA update from PC...\r\n");

  while(1){
    uint8_t b;
    if (HAL_UART_Receive(&huart2, &b, 1, 1000) != HAL_OK) continue;
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

    if (length > 0 && length <= 256){
      if (HAL_UART_Receive(&huart2, payload, length, 1000) != HAL_OK){
        send_response(NAK);
        continue;
      }
    }

    if (HAL_UART_Receive(&huart2, &checksum, 1, 1000) != HAL_OK){
      send_response(NAK);
      continue;
    }
    
    uint8_t calculated_checksum = 0;
    for (int i = 0; i < 8; i++) calculated_checksum += header[i];
    for (int i = 0; i < length; i++) calculated_checksum += payload[i];

    if(calculated_checksum != checksum){
      send_response(NAK);
      continue;
    }

    if (cmd == CMD_HELLO){
      send_response(ACK);
    }
    else if (cmd == CMD_BEGIN){
      expected_seq = 0;
      total_received = 0;
      ext_flash_addr = EXT_FLASH_ENC_ADDR;
      send_response(ACK);
    }
    else if (cmd == CMD_DATA) {
      if (seq == expected_seq) {
        if (seq == 0) {
          // Erase sectors in external flash for incoming encrypted package (up to 448KB)
          for (int i = 0; i < 32; i++) {
            W25Q64_EraseSector(EXT_FLASH_ENC_ADDR + i * 0x1000);
          }
        }
        W25Q64_WriteStream(ext_flash_addr, payload, length);
        ext_flash_addr += length;
        total_received += length;
        expected_seq++;
        send_response(ACK);
      } else {
        send_response(NAK);
      }
    }
    else if (cmd == CMD_END) {
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
      hkdf_sha256(OTA_SALT, sizeof(OTA_SALT) - 1,
                  MASTER_KEY, sizeof(MASTER_KEY) - 1,
                  device_uid, 12,
                  device_aes_key, 32);

      // Decrypt staging package, verify it, and install to internal flash
      int update_ok = decrypt_and_install_firmware(EXT_FLASH_ENC_ADDR, EXT_FLASH_DEC_ADDR, total_received, device_aes_key);

      // Wipe derived device key and UID from RAM
      secure_memzero(device_aes_key, sizeof(device_aes_key));
      secure_memzero(device_uid, sizeof(device_uid));

      if (update_ok) {
        send_response(ACK);
        printf("[OTA] Firmware update successful! Jumping to new App...\r\n");
        HAL_Delay(500);
        NVIC_SystemReset();
      } else {
        send_response(NAK);
        printf("[OTA ERROR] Decryption, verification, or installation failed!\r\n");
      }
    }
  }
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_SPI1_Init();
  /* USER CODE BEGIN 2 */
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
    wait_for_ota_package();
  }
  
  // Verify the stored firmware (header and app binary)
  if (verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
    // Check if the MSP (Main Stack Pointer) value is valid (should be in SRAM range)
    if (((*(__IO uint32_t*)APP_START_ADDRESS) & 0x2FF00000) == 0x20000000) {
      jump_to_application(APP_START_ADDRESS);
    } else {
      printf("BOOT ERROR: Invalid MSP address. Entering RECOVERY mode.\r\n");
      printf("Waiting for new OTA package...\r\n");
      wait_for_ota_package();
    }
  } else {
    printf("No valid/verified App found. Entering RECOVERY mode.\r\n");
    wait_for_ota_package();
  }
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 16;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_32;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 10;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : W25Q_CS_Pin */
  GPIO_InitStruct.Pin = W25Q_CS_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(W25Q_CS_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
void W25Q64_WaitForWriteEnd(void)
{
  uint8_t cmd = 0x05; // Read Status Register-1
  uint8_t status = 0;
  uint32_t timeout = 5000; // Timeout counter (ms)

  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, &cmd, 1, 100);
  do {
    HAL_SPI_Receive(&hspi1, &status, 1, 100);
    HAL_Delay(1);
    timeout--;
    if (timeout == 0) {
      printf("[W25Q64 ERROR] Write timeout!\r\n");
      break;
    }
  } while ((status & 0x01) == 0x01); // Wait until WIP bit is cleared
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
}

void W25Q64_WriteEnable(void)
{
  uint8_t cmd = 0x06; // Write Enable
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, &cmd, 1, 100);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
}

void W25Q64_ReadData(uint32_t ReadAddr, uint8_t *pData, uint16_t read_size)
{
  uint8_t cmd[4];
  cmd[0] = 0x03; // Read Data
  cmd[1] = (ReadAddr >> 16) & 0xFF;
  cmd[2] = (ReadAddr >> 8) & 0xFF;
  cmd[3] = ReadAddr & 0xFF;

  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, cmd, 4, 100);
  HAL_SPI_Receive(&hspi1, pData, read_size, 1000);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
}

void W25Q64_EraseSector(uint32_t SectorAddr)
{
  W25Q64_WriteEnable();

  uint8_t cmd[4];
  cmd[0] = 0x20; // Sector Erase (4KB)
  cmd[1] = (SectorAddr >> 16) & 0xFF;
  cmd[2] = (SectorAddr >> 8) & 0xFF;
  cmd[3] = SectorAddr & 0xFF;

  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, cmd, 4, 100);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);

  W25Q64_WaitForWriteEnd();
}

void W25Q64_WritePage(uint32_t PageAddr, uint8_t *pData, uint16_t write_size)
{
  if (write_size > 256) return; // Max page size is 256 bytes

  W25Q64_WriteEnable();

  uint8_t cmd[4];
  cmd[0] = 0x02; // Page Program
  cmd[1] = (PageAddr >> 16) & 0xFF;
  cmd[2] = (PageAddr >> 8) & 0xFF;
  cmd[3] = PageAddr & 0xFF;

  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, cmd, 4, 100);
  HAL_SPI_Transmit(&hspi1, pData, write_size, 1000);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);

  W25Q64_WaitForWriteEnd();
}

void W25Q64_WriteStream(uint32_t StartAddr, uint8_t *pData, uint16_t write_size)
{
  uint16_t remain = write_size;
  uint32_t current_addr = StartAddr;
  uint8_t *ptr = pData;

  while (remain > 0){
    uint16_t page_offset = current_addr % 256;
    uint16_t space_in_page = 256 - page_offset;
    uint16_t write_size = (remain < space_in_page) ? remain : space_in_page;

    W25Q64_WritePage(current_addr, ptr, write_size);

    current_addr += write_size;
    ptr += write_size;
    remain -= write_size;
  }
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
