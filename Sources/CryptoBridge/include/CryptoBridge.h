#ifndef CRYPTO_BRIDGE_H
#define CRYPTO_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
int cd_initialize(void);
const char *cd_version(void);
void cd_release(void *buffer, size_t length);
int cd_digest(const char *name, const uint8_t *input, size_t length,
              uint8_t **output, size_t *output_length);
int cd_cipher(const char *name, int encrypt, int padding,
              const uint8_t *key, size_t key_length,
              const uint8_t *iv, size_t iv_length,
              const uint8_t *input, size_t input_length,
              uint8_t **output, size_t *output_length);
int cd_generate(const char *algorithm, int bits, char **public_pem,
                size_t *public_length, char **private_pem, size_t *private_length);
int cd_validate_key(const char *algorithm, const char *pem, int is_private);
int cd_validate_pair(const char *public_pem, const char *private_pem);
int cd_sm2_import(const uint8_t *bytes, size_t length, int is_private,
                  char **pem, size_t *pem_length);
int cd_sm2_export(const char *pem, int is_private, uint8_t **bytes, size_t *length);
int cd_rsa_component(const char *pem, int is_private, int component,
                     uint8_t **bytes, size_t *length);
int cd_asymmetric(const char *algorithm, int encrypt, int oaep,
                 const char *pem, const uint8_t *input, size_t input_length,
                 uint8_t **output, size_t *output_length);
#endif
