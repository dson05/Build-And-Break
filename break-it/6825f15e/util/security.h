#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stddef.h>

#define MASTER_KEY_LEN 32
#define CARD_SECRET_LEN 32
#define SESSION_KEY_LEN 32
#define NONCE_LEN 16
#define SHA256_HEX_LEN 64

int random_bytes_secure(unsigned char *buf, size_t len);
void bytes_to_hex(const unsigned char *bytes, size_t len, char *out);
int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len);
int hmac_sha256_hex(const unsigned char *key, size_t key_len, const char *message,
                    char *out_hex, size_t out_size);
int hmac_sha256_bytes(const unsigned char *key, size_t key_len, const char *message,
                      unsigned char *out, size_t out_len);
int secure_bytes_equal(const unsigned char *left, const unsigned char *right, size_t len);

#endif
