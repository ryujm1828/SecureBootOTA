/**
  ******************************************************************************
  * @file           : w25q64.c
  * @brief          : W25Q64 SPI Flash Driver Implementation
  ******************************************************************************
  */

#include "w25q64.h"
#include <stdio.h>

extern SPI_HandleTypeDef hspi1;

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

