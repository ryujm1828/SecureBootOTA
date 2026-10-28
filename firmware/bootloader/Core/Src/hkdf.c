/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : hkdf.c
  * @brief          : HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869) implementation
  ******************************************************************************
  */
/* USER CODE END Header */

#include "hkdf.h"
#include "sha256.h"
#include <string.h>

#define HMAC_SHA256_BLOCK_SIZE  64
#define HMAC_SHA256_DIGEST_SIZE 32

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32])
{
  SHA256_CTX ctx;
  uint8_t k0[HMAC_SHA256_BLOCK_SIZE];
  uint8_t ipad[HMAC_SHA256_BLOCK_SIZE];
  uint8_t opad[HMAC_SHA256_BLOCK_SIZE];
  uint8_t inner_hash[HMAC_SHA256_DIGEST_SIZE];

  memset(k0, 0, sizeof(k0));

  // If key is longer than block size, hash it first
  if (key_len > HMAC_SHA256_BLOCK_SIZE) {
    sha256_init(&ctx);
    sha256_update(&ctx, key, key_len);
    sha256_final(&ctx, k0);
  } else {
    memcpy(k0, key, key_len);
  }

  // XOR key with ipad and opad
  for (int i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5C;
  }

  // Inner hash: SHA256(K_ipad || data)
  sha256_init(&ctx);
  sha256_update(&ctx, ipad, HMAC_SHA256_BLOCK_SIZE);
  if (data && data_len > 0) {
    sha256_update(&ctx, data, data_len);
  }
  sha256_final(&ctx, inner_hash);

  // Outer hash: SHA256(K_opad || inner_hash)
  sha256_init(&ctx);
  sha256_update(&ctx, opad, HMAC_SHA256_BLOCK_SIZE);
  sha256_update(&ctx, inner_hash, HMAC_SHA256_DIGEST_SIZE);
  sha256_final(&ctx, out);
}

void hkdf_sha256(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len)
{
  uint8_t prk[HMAC_SHA256_DIGEST_SIZE];
  uint8_t null_salt[HMAC_SHA256_DIGEST_SIZE] = {0};

  // Step 1: HKDF-Extract (PRK = HMAC-SHA256(salt, IKM))
  if (salt == NULL || salt_len == 0) {
    salt = null_salt;
    salt_len = sizeof(null_salt);
  }
  hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

  // Step 2: HKDF-Expand
  uint8_t t[HMAC_SHA256_DIGEST_SIZE];
  size_t t_len = 0;
  size_t generated = 0;
  uint8_t counter = 1;

  while (generated < okm_len) {
    SHA256_CTX ctx;
    uint8_t k0[HMAC_SHA256_BLOCK_SIZE] = {0};
    uint8_t ipad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t opad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t inner_hash[HMAC_SHA256_DIGEST_SIZE];

    memcpy(k0, prk, HMAC_SHA256_DIGEST_SIZE);
    for (int i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
      ipad[i] = k0[i] ^ 0x36;
      opad[i] = k0[i] ^ 0x5C;
    }

    // T(i) = HMAC(PRK, T(i-1) || info || counter)
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, HMAC_SHA256_BLOCK_SIZE);
    if (t_len > 0) {
      sha256_update(&ctx, t, t_len);
    }
    if (info && info_len > 0) {
      sha256_update(&ctx, info, info_len);
    }
    sha256_update(&ctx, &counter, 1);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, HMAC_SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, HMAC_SHA256_DIGEST_SIZE);
    sha256_final(&ctx, t);
    t_len = HMAC_SHA256_DIGEST_SIZE;

    size_t to_copy = (okm_len - generated > HMAC_SHA256_DIGEST_SIZE) ? HMAC_SHA256_DIGEST_SIZE : (okm_len - generated);
    memcpy(okm + generated, t, to_copy);
    generated += to_copy;
    counter++;
  }
}
