#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stddef.h>
#include <stdint.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define SECRET_SIZE 32
#define SECRET_HEX_SIZE 65

/* fills buf with cryptographically random bytes */
int rand_bytes(unsigned char *buf, size_t len);

/* writes iv || ciphertext || tag into out using AES-256-GCM */
int aead_seal(const unsigned char *key, const unsigned char *pt, size_t pt_len, unsigned char *out);

/* parses iv || ciphertext || tag from in; returns plaintext length or -1 */
int aead_open(const unsigned char *key, const unsigned char *in, size_t in_len, unsigned char *out);

void to_hex(const unsigned char *in, size_t len, char *out);
int from_hex(const char *in, unsigned char *out, size_t len);

#endif
