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

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
// Pack structures to 1-byte alignment
#pragma pack(push, 1)
typedef struct {
  uint8_t magic[4];             // 4 bytes: "OTAF"
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
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
#include <stdio.h>
#include <string.h>
// _write() function is used by printf() to send data over UART
int _write(int file, char *ptr, int len)
{
    // Send data over UART
    HAL_UART_Transmit(&huart2, (uint8_t*)ptr, len, 1000);
    return len;
}

#define EXPECTED_MAGIC "OTAF"
#define EXPECTED_FORMAT_VERSION 0x0001
#define EXPECTED_HEADER_SIZE 120
#define EXPECTED_TARGET_ID 0x0411

int validate_ota_header(const ota_header_t *header){
  if (memcmp(header->magic, EXPECTED_MAGIC, 4) != 0) {
    printf("[ERROR] Invalid magic number in OTA header. Expected: %s, Got: %s\r\n", EXPECTED_MAGIC, header->magic);
    return -1;
  }
  if (header->format_version != EXPECTED_FORMAT_VERSION) {
    printf("[ERROR] Unsupported format version in OTA header. Expected: 0x%04X, Got: 0x%04X\r\n", EXPECTED_FORMAT_VERSION, header->format_version);
    return -2;
  }
  if (header->header_size != EXPECTED_HEADER_SIZE) {
    printf("[ERROR] Unexpected header size in OTA header. Expected: %d, Got: %d\r\n", EXPECTED_HEADER_SIZE, header->header_size);
    return -3;
  }
  if (header->target_id != EXPECTED_TARGET_ID) {
    printf("[ERROR] Target ID mismatch in OTA header. Expected: 0x%08X, Got: 0x%08lX\r\n", EXPECTED_TARGET_ID, header->target_id);
    return -4;
  }
  printf("[Success] OTA header validation passed.\r\n");
  printf("Format Version: 0x%04X, Header Size: %d, Target ID: 0x%08lX\r\n", header->format_version, header->header_size, header->target_id);
  return 0; // Header is valid
} 

// OTA Protocol CONSTANTS
#define FRAME_MAGIC 0xABCD
#define CMD_HELLO 1
#define CMD_BEGIN 2
#define CMD_DATA 3
#define CMD_END 4
#define ACK 0X06
#define NAK 0X15

// Function to send a response (ACK or NAK) over UART
void send_response(uint8_t res){
  HAL_UART_Transmit(&huart2, &res, 1, 100);
}

void wait_for_ota_package(void){
  uint8_t header[8];
  uint8_t payload[256];
  uint8_t checksum;

  uint16_t expected_seq = 0;
  uint32_t total_received = 0;

  printf("\r\n Waiting for OTA update form PC...\r\n")

  while(1){
    //Wait for the header
    if (HAL_UART_Receive(&huart2, header, 8, 1000) != HAL_OK) continue;

    uint16_t magic = header[0] | (header[1] << 8);
    uint8_t version = header[2];
    uint8_t cmd = header[3];
    uint16_t seq = header[4] | (header[5] << 8);
    uint8_t length = header[6] | (header[7] << 8);

    if (magic != FRAME_MAGIC) continue;

    if (length > 0 && length <= 256){
      if (HAL_UART_Receive(&huart2, payload, length, 1000) != HAL_OK)
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
    printf("[ERROR] Checksum mismatch. Expected: 0x%02X, Got: 0x%02lX\r\n", checksum, calculated_checksum);
    send_response(NAK);
    continue;
  }

  if (cmd == CMD_HELLO){
    printf("[HEllo] PC connected.\r\n");
    send_response(ACK);
  }
  else if (cmd == CMD_BEGIN){
    uint32_t total_size = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24);
    printf("[BEGIN] Starting OTA... Total bytes: %ld\r\n", total_size);
    expected_seq = 0;
    total_received = 0;
    send_response(ACK);
  }
  else if (cmd == CMD_DATA){
    if (seq != expected_seq){
      printf("[ERROR] Sequence mismatch. Expected: %d, Got: %d\r\n", expected_seq, seq);
      send_response(NAK);
      continue;
    }
    printf("[DATA] Received DATA command. Sequence: %d, Length: %d\r\n", seq, length);
    
    total_received += length;
    expected_seq++;
    send_response(ACK);
  }
  else if (cmd == CMD_END){
    printf("[END] Received END command. Total bytes received: %ld\r\n", total_received);
    send_response(ACK);
    
    printf("Rebooting system...\r\n");
    HAL_Delay(1000);
    NVIC_SystemReset();
  }
  else {
    printf("[ERROR] Unknown command received: %d\r\n", cmd);
    send_response(NAK);
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
  /* USER CODE BEGIN 2 */
  
  //App start physicaladdress
  #define APP_START_ADDRESS 0x08010000

  printf("\r\n===========================\r\n");
  printf("Bootloader Started\r\n");
  printf("Checking App at Address: 0x%08X\r\n",APP_START_ADDRESS);

  // Check if a valid application exists
  // Check if the first word is a valid RAM address (0x20000000~0x200FFFFF)
  if (((*(__IO uint32_t*)APP_START_ADDRESS) & 0x2FF00000 ) == 0x20000000)
  {

	  printf("Valid App found. Jumping to App...\r\n");
	  HAL_Delay(50); // Wait for UART transmission to complete

	  // Disable all interrupts before jumping to the application
	  __disable_irq();

	  //SysTick disable
	  SysTick->CTRL = 0;
	  SysTick->LOAD = 0;
	  SysTick->VAL = 0;

	  HAL_DeInit(); // Initialize the HAL library

	  for (int i = 0; i < 8; i++) {
		  NVIC->ICER[i] = 0xFFFFFFFF;
	      NVIC->ICPR[i] = 0xFFFFFFFF;
	  }

    // start address + 4bytes is the real start address in Cortex-M series
	  uint32_t jump_address = *(__IO uint32_t*) (APP_START_ADDRESS + 4);
	  void (*app_reset_handler)(void) = (void (*)(void))jump_address;

	  //Enable interrupts
	  __enable_irq();

	  // Set MSP to the value at the start of the application
	  __set_MSP(*(__IO uint32_t*)APP_START_ADDRESS);

	  //Jump to the application reset handler
	  app_reset_handler();
  }
  else
  {
	  //There is no valid application
	  printf("No valid App. Entering RECOVERY mode.\r\n");
    
    // Wait for OTA package from PC
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
  HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : LD2_Pin */
  GPIO_InitStruct.Pin = LD2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LD2_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

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
