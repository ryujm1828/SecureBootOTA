/**
  ******************************************************************************
  * @file           : secure_utils.c
  * @brief          : Implementation of secure utilities
  ******************************************************************************
  */

#include "secure_utils.h"

// Secure memory wipe to prevent compiler dead-store optimization
void secure_memzero(void *v, size_t n)
{
  volatile uint8_t *p = (volatile uint8_t *)v;
  while (n--) {
    *p++ = 0;
  }
}

// Constant-time memory compare to prevent timing side-channel attacks
int constant_time_memcmp(const void *a, const void *b, size_t len)
{
  const uint8_t *p1 = (const uint8_t *)a;
  const uint8_t *p2 = (const uint8_t *)b;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (p1[i] ^ p2[i]);
  }
  return diff;
}

