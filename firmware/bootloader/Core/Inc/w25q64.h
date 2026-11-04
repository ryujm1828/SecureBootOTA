/**
  ******************************************************************************
  * @file           : w25q64.h
  * @brief          : W25Q64 SPI Flash Driver Header
  ******************************************************************************
  */

#ifndef __W25Q64_H
#define __W25Q64_H

#include "main.h"

#ifdef __cplusplus
extern "C" {
#endif

int W25Q64_WaitForWriteEnd(void);
int W25Q64_WriteEnable(void);
int W25Q64_ReadData(uint32_t ReadAddr, uint8_t *pData, uint16_t read_size);
int W25Q64_EraseSector(uint32_t SectorAddr);
int W25Q64_WritePage(uint32_t PageAddr, uint8_t *pData, uint16_t write_size);
int W25Q64_WriteStream(uint32_t StartAddr, uint8_t *pData, uint16_t write_size);

#ifdef __cplusplus
}
#endif

#endif /* __W25Q64_H */

