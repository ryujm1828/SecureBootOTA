/**
  ******************************************************************************
  * @file           : secure_utils.h
  * @brief          : Constant-time comparison and secure memory wiping utilities
  ******************************************************************************
  */

#ifndef __SECURE_UTILS_H
#define __SECURE_UTILS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Securely zero memory to prevent compiler dead-store optimization.
 * @param  v: Pointer to memory buffer
 * @param  n: Number of bytes to zero
 */
void secure_memzero(void *v, size_t n);

/**
 * @brief  Constant-time memory compare to prevent timing side-channel attacks.
 * @param  a: Pointer to first buffer
 * @param  b: Pointer to second buffer
 * @param  len: Number of bytes to compare
 * @retval 0 if equal, non-zero if different
 */
int constant_time_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __SECURE_UTILS_H */

