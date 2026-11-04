/**
  ******************************************************************************
  * @file           : w25q64.c
  * @brief          : W25Q64 SPI Flash Driver Implementation
  ******************************************************************************
  */

#include "w25q64.h"
#include <stdio.h>

extern SPI_HandleTypeDef hspi1;

int W25Q64_WaitForWriteEnd(void)
{
  uint8_t cmd = 0x05;
  uint8_t status = 0;
  uint32_t tickstart = HAL_GetTick();
  uint32_t timeout = 5000;
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  if (HAL_SPI_Transmit(&hspi1, &cmd, 1, 100) != HAL_OK) {
    HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
    return 0;
  }
  
  do {
    if (HAL_SPI_Receive(&hspi1, &status, 1, 100) != HAL_OK) {
      HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
      return 0;
    }
    
    if ((HAL_GetTick() - tickstart) >= timeout) {
      printf("[W25Q64 ERROR] Write timeout!\r\n");
      HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
      return 0;
    }
  } while ((status & 0x01) == 0x01);
  
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
  return 1;
}

int W25Q64_WriteEnable(void)
{
  uint8_t cmd = 0x06;
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_StatusTypeDef res = HAL_SPI_Transmit(&hspi1, &cmd, 1, 100);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
  return (res == HAL_OK) ? 1 : 0;
}

int W25Q64_ReadData(uint32_t ReadAddr, uint8_t *pData, uint32_t read_size)
{
  if (read_size == 0) return 1;
  uint8_t cmd[4];
  cmd[0] = 0x03;
  cmd[1] = (ReadAddr >> 16) & 0xFF;
  cmd[2] = (ReadAddr >> 8) & 0xFF;
  cmd[3] = ReadAddr & 0xFF;
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_StatusTypeDef res1 = HAL_SPI_Transmit(&hspi1, cmd, 4, 100);
  HAL_StatusTypeDef res2 = HAL_SPI_Receive(&hspi1, pData, (uint16_t)read_size, 1000);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
  return (res1 == HAL_OK && res2 == HAL_OK) ? 1 : 0;
}

int W25Q64_EraseSector(uint32_t SectorAddr)
{
  if (!W25Q64_WriteEnable()) return 0;
  uint8_t cmd[4];
  cmd[0] = 0x20;
  cmd[1] = (SectorAddr >> 16) & 0xFF;
  cmd[2] = (SectorAddr >> 8) & 0xFF;
  cmd[3] = SectorAddr & 0xFF;
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  HAL_StatusTypeDef res = HAL_SPI_Transmit(&hspi1, cmd, 4, 100);
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
  if (res != HAL_OK) return 0;
  return W25Q64_WaitForWriteEnd();
}

int W25Q64_WritePage(uint32_t PageAddr, uint8_t *pData, uint16_t write_size)
{
  if (write_size == 0 || write_size > 256) return 0;
  if (!W25Q64_WriteEnable()) return 0;
  uint8_t cmd[4];
  cmd[0] = 0x02;
  cmd[1] = (PageAddr >> 16) & 0xFF;
  cmd[2] = (PageAddr >> 8) & 0xFF;
  cmd[3] = PageAddr & 0xFF;
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_RESET);
  if (HAL_SPI_Transmit(&hspi1, cmd, 4, 100) != HAL_OK ||
      HAL_SPI_Transmit(&hspi1, pData, write_size, 1000) != HAL_OK) {
    HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
    return 0;
  }
  HAL_GPIO_WritePin(W25Q_CS_GPIO_Port, W25Q_CS_Pin, GPIO_PIN_SET);
  return W25Q64_WaitForWriteEnd();
}

int W25Q64_WriteStream(uint32_t StartAddr, uint8_t *pData, uint16_t write_size)
{
  uint16_t remain = write_size;
  uint32_t current_addr = StartAddr;
  uint8_t *ptr = pData;
  while (remain > 0) {
    uint16_t page_offset = current_addr % 256;
    uint16_t space_in_page = 256 - page_offset;
    uint16_t chunk_len = (remain < space_in_page) ? remain : space_in_page;
    if (!W25Q64_WritePage(current_addr, ptr, chunk_len)) {
      return 0;
    }
    current_addr += chunk_len;
    ptr += chunk_len;
    remain -= chunk_len;
  }
  return 1;
}