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
void W25Q64_ReadData(uint32_t ReadAddr, uint8_t *pData, uint16_t Size);
void W25Q64_EraseSector(uint32_t SectorAddr);
void W25Q64_WritePage(uint32_t PageAddr, uint8_t *pData, uint16_t Size);
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

#define HEADER_START_ADDRESS 0x08010000
#define APP_START_ADDRESS    0x08010200

#define EXPECTED_MAGIC ( (uint32_t)'O' | ((uint32_t)'T' << 8) | ((uint32_t)'A' << 16) | ((uint32_t)'F' << 24) )
#define EXPECTED_FORMAT_VERSION 0x0001
#define EXPECTED_HEADER_SIZE 120
#define EXPECTED_TARGET_ID 0x0411

uint8_t current_sec_version = 2;

// ECDSA public key in C array format (NIST P-256)
const uint8_t ecdsa_public_key[64] = {
    0xf6, 0x6b, 0x60, 0x08, 0xf5, 0xf1, 0xa8, 0xab, 0x02, 0x04, 0xd5, 0x93, 0x8d, 0x55, 0x12, 0xe3,
    0x70, 0xdc, 0x6f, 0x7d, 0xeb, 0x53, 0x14, 0xaf, 0x6b, 0xbe, 0x07, 0x1f, 0x7e, 0x91, 0xf4, 0x0f,
    0x58, 0xd5, 0x42, 0xe4, 0x03, 0x92, 0xf7, 0x99, 0x43, 0xbd, 0x06, 0x68, 0x90, 0x65, 0x61, 0x77,
    0x68, 0x25, 0xa8, 0xdb, 0x58, 0x9f, 0x2d, 0xb3, 0x9d, 0x39, 0x57, 0xb7, 0x68, 0x37, 0x14, 0x6f
};

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

  if (hdr->image_version < current_sec_version) {
    printf("[SECURITY] Rollback detected! Img Ver: %lu < Min Ver: %u\r\n", 
           (unsigned long)hdr->image_version, current_sec_version);
    return 0;
  }

  uint8_t header_hash[32];
  SHA256_CTX sha_ctx;
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, (const uint8_t *)header_address, 56);
  sha256_final(&sha_ctx, header_hash);

  if (uECC_verify(ecdsa_public_key, header_hash, 32, hdr->signature, uECC_secp256r1()) != 1) {
    printf("[SECURITY] ECDSA Signature Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  uint8_t app_hash[32];
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, (const uint8_t *)app_address, hdr->image_size);
  sha256_final(&sha_ctx, app_hash);

  if (memcmp(app_hash, hdr->payload_sha256, 32) != 0) {
    printf("[SECURITY] App SHA-256 Hash Mismatch! Firmware Rejected.\r\n");
    return 0;
  }

  printf("[SECURITY] Verification Success! (Version: %lu, Size: %lu bytes)\r\n", 
         (unsigned long)hdr->image_version, (unsigned long)hdr->image_size);
  return 1;
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

  __enable_irq();
  __set_MSP(*(__IO uint32_t *)app_address);
  app_reset_handler();
}

void wait_for_ota_package(void){
  uint8_t header[8];
  uint8_t payload[256];
  uint8_t checksum;

  uint16_t expected_seq = 0;
  uint32_t total_received = 0;
  uint32_t header_addr = HEADER_START_ADDRESS;
  uint32_t flash_write_addr = APP_START_ADDRESS;

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
      flash_write_addr = APP_START_ADDRESS;

      HAL_FLASH_Unlock();
      __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | 
                             FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

      FLASH_EraseInitTypeDef EraseInitStruct;
      uint32_t SectorError;
      EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
      EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
      EraseInitStruct.Sector = FLASH_SECTOR_4; // Sector 4 ~ 7
      EraseInitStruct.NbSectors = 4;

      HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError);
      HAL_FLASH_Lock();

      send_response(ACK);
    }
    else if (cmd == CMD_DATA) {
      if (seq == expected_seq) {
        uint8_t *data_ptr = payload;
        uint16_t data_len = length;

        if (seq == 0) {
          const ota_header_t *ota_hdr = (const ota_header_t *)payload;
          if (!validate_ota_header(ota_hdr) || (ota_hdr->image_version < current_sec_version)) {
            send_response(NAK);
            continue;
          }

          // 헤더 120바이트 기록
          HAL_FLASH_Unlock();
          __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | 
                                 FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

          for (int i = 0; i < 120; i++) {
            HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, header_addr + i, payload[i]);
          }
          HAL_FLASH_Lock();

          data_ptr = &payload[120];
          data_len = length - 120;
        }

        // 앱 바이너리 기록
        HAL_FLASH_Unlock();
        __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | 
                               FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

        for (int i = 0; i < data_len; i++) {
          HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, flash_write_addr + i, data_ptr[i]);
        }
        flash_write_addr += data_len;
        HAL_FLASH_Lock();

        total_received += length;
        expected_seq++;
        send_response(ACK);
      } else {
        send_response(NAK);
      }
    }
    else if (cmd == CMD_END) {
      send_response(ACK);

      // 플래시에 구워진 새 펌웨어 통합 검증!
      if (verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
        printf("[BOARD] OTA Update Verified Successfully! Rebooting...\r\n");
        HAL_Delay(1000);
        NVIC_SystemReset();
      } else {
        printf("[BOARD] ERROR: Flashed Firmware Verification Failed!\r\n");
      }
    }
    else {
      send_response(NAK);
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

  /*
  // Verify firmware stored in internal flash
  if (verify_stored_firmware(HEADER_START_ADDRESS, APP_START_ADDRESS)) {
    if (((*(__IO uint32_t*)APP_START_ADDRESS) & 0x2FF00000) == 0x20000000) {
      jump_to_application(APP_START_ADDRESS);
    } else {
      printf("BOOT ERROR: Invalid MSP address. Entering RECOVERY mode.\r\n");
      wait_for_ota_package();
    }
  } else {
    printf("No valid/verified App found. Entering RECOVERY mode.\r\n");
    wait_for_ota_package();
  }
  */

  printf("\r\n========================================\r\n");
  printf("W25Q64 SPI Communication Test\r\n");

  // Read JEDEC ID (0x9F)
  uint8_t cmd = 0x9F;
  uint8_t id_buf[3] = {0};

  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, &cmd, 1, 100);
  HAL_SPI_Receive(&hspi1, id_buf, 3, 100);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);

  printf("JEDEC ID : 0x%02X 0x%02X 0x%02X\r\n", id_buf[0], id_buf[1], id_buf[2]);

  if (id_buf[0] == 0xEF && id_buf[1] == 0x40 && id_buf[2] == 0x17) {
    printf("-> [SUCCESS] W25Q64 is properly connected!\r\n");
  } else {
    printf("-> [ERROR] Unknown Chip or SPI Connection Failed.\r\n");
  }

  printf("\r\n[TEST] W25Q64 Erase & Write Test...\r\n");

  uint8_t write_buf[16] = "Hello OTA!";
  uint8_t read_buf[16] = {0};
  uint32_t target_addr = 0x000000;

  // Erase sector
  W25Q64_EraseSector(target_addr);
  printf("- Sector Erased.\r\n");

  // Write page
  W25Q64_WritePage(target_addr, write_buf, 10);
  printf("- Data Written.\r\n");

  // Read back
  W25Q64_ReadData(target_addr, read_buf, 10);
  printf("- Read Back: %s\r\n", read_buf);

  if (memcmp(write_buf, read_buf, 10) == 0) {
    printf("=> [SUCCESS] Flash Memory R/W Test Passed!\r\n");
  } else {
    printf("=> [ERROR] Data Mismatch!\r\n");
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

void W25Q64_ReadData(uint32_t ReadAddr, uint8_t *pData, uint16_t Size)
{
  uint8_t cmd[4];
  cmd[0] = 0x03; // Read Data
  cmd[1] = (ReadAddr >> 16) & 0xFF;
  cmd[2] = (ReadAddr >> 8) & 0xFF;
  cmd[3] = ReadAddr & 0xFF;

  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, cmd, 4, 100);
  HAL_SPI_Receive(&hspi1, pData, Size, 1000);
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

void W25Q64_WritePage(uint32_t PageAddr, uint8_t *pData, uint16_t Size)
{
  if (Size > 256) return; // Max page size is 256 bytes

  W25Q64_WriteEnable();

  uint8_t cmd[4];
  cmd[0] = 0x02; // Page Program
  cmd[1] = (PageAddr >> 16) & 0xFF;
  cmd[2] = (PageAddr >> 8) & 0xFF;
  cmd[3] = PageAddr & 0xFF;

  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_SPI_Transmit(&hspi1, cmd, 4, 100);
  HAL_SPI_Transmit(&hspi1, pData, Size, 1000);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);

  W25Q64_WaitForWriteEnd();
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
