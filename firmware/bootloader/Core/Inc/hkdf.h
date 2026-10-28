/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : hkdf.h
  * @brief          : Header for HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)
  ******************************************************************************
  */
/* USER CODE END Header */

#ifndef HKDF_H
#define HKDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Calculate HMAC-SHA256.
 * @param  key      Secret key
 * @param  key_len  Length of secret key
 * @param  data     Input data
 * @param  data_len Length of input data
 * @param  out      Output 32-byte HMAC
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]);

/**
 * @brief  HMAC-based Key Derivation Function (HKDF) using SHA-256 (RFC 5869).
 * @param  salt     Salt value (optional, can be NULL)
 * @param  salt_len Length of salt
 * @param  ikm      Input keying material
 * @param  ikm_len  Length of IKM
 * @param  info     Context and application specific information (optional)
 * @param  info_len Length of info
 * @param  okm      Output keying material
 * @param  okm_len  Length of output keying material (in bytes)
 */
void hkdf_sha256(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_H */

