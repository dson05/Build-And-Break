#include "security.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>

int random_bytes_secure(unsigned char *buf, size_t len)
{
    // wrapper around openssl randomness
    return RAND_bytes(buf, (int) len) == 1;
}

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out)
{
    static const char hex_digits[] = "0123456789abcdef";
    size_t i;

    // turn bytes into text for files and messages
    for (i = 0; i < len; i++)
    {
        out[i * 2] = hex_digits[bytes[i] >> 4];
        out[i * 2 + 1] = hex_digits[bytes[i] & 0x0f];
    }

    out[len * 2] = '\0';
}

static int hex_value(char c)
{
    // helper for hex parsing
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    size_t i;
    int hi;
    int lo;

    // wrong length means bad input
    if (hex == NULL || strlen(hex) != out_len * 2)
        return 0;

    for (i = 0; i < out_len; i++)
    {
        hi = hex_value(hex[i * 2]);
        lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        out[i] = (unsigned char) ((hi << 4) | lo);
    }

    return 1;
}

int hmac_sha256_hex(const unsigned char *key, size_t key_len, const char *message,
                    char *out_hex, size_t out_size)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (out_size < SHA256_HEX_LEN + 1)
        return 0;

    if (HMAC(EVP_sha256(), key, (int) key_len, (const unsigned char *) message,
             strlen(message), digest, &digest_len) == NULL || digest_len != 32)
    {
        return 0;
    }

    // same hmac, just returned as hex
    bytes_to_hex(digest, digest_len, out_hex);
    return 1;
}

int hmac_sha256_bytes(const unsigned char *key, size_t key_len, const char *message,
                      unsigned char *out, size_t out_len)
{
    unsigned int digest_len = 0;

    // we expect a sha256-sized output here
    if (out_len != 32)
        return 0;

    if (HMAC(EVP_sha256(), key, (int) key_len, (const unsigned char *) message,
             strlen(message), out, &digest_len) == NULL || digest_len != out_len)
    {
        return 0;
    }

    return 1;
}

int secure_bytes_equal(const unsigned char *left, const unsigned char *right, size_t len)
{
    // constant-time compare for secrets
    return CRYPTO_memcmp(left, right, len) == 0;
}
