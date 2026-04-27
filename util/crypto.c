#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

int rand_bytes(unsigned char *buf, size_t len) {

    return RAND_bytes(buf, (int)len) == 1;
}

/* AES-256-GCM seal: writes iv || ciphertext || tag */
int aead_seal(const unsigned char *key, const unsigned char *pt, size_t pt_len, unsigned char *out) {

    EVP_CIPHER_CTX *ctx;
    unsigned char *iv = out;
    unsigned char *ct = out + IV_SIZE;
    unsigned char *tag = out + IV_SIZE + pt_len;
    int len;
    int ct_len;

    if (!rand_bytes(iv, IV_SIZE)) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return IV_SIZE + ct_len + TAG_SIZE;
}

/* AES-256-GCM open: reads iv || ciphertext || tag; returns plaintext length or -1 */
int aead_open(const unsigned char *key, const unsigned char *in, size_t in_len, unsigned char *out) {

    EVP_CIPHER_CTX *ctx;
    const unsigned char *iv;
    const unsigned char *ct;
    unsigned char *tag;
    int ct_len;
    int len;
    int pt_len;

    if (in_len < IV_SIZE + TAG_SIZE) {
        return -1;
    }

    iv = in;
    ct = in + IV_SIZE;
    ct_len = (int)(in_len - IV_SIZE - TAG_SIZE);
    tag = (unsigned char *)(in + in_len - TAG_SIZE);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    pt_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    /* fails when the tag does not authenticate the ciphertext */
    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    pt_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return pt_len;
}

void to_hex(const unsigned char *in, size_t len, char *out) {

    static const char alphabet[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[2 * i]     = alphabet[in[i] >> 4];
        out[2 * i + 1] = alphabet[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

static int hex_val(char c) {

    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int from_hex(const char *in, unsigned char *out, size_t len) {

    size_t i;
    int hi;
    int lo;

    for (i = 0; i < len; i++) {
        hi = hex_val(in[2 * i]);
        lo = hex_val(in[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}
