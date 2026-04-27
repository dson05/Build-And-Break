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
    int len, ct_len, ret = -1;

    if (!rand_bytes(iv, IV_SIZE)) return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto out;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto out;
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) goto out;
    ret = IV_SIZE + ct_len + TAG_SIZE;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* AES-256-GCM open: returns plaintext length or -1 on bad tag */
int aead_open(const unsigned char *key, const unsigned char *in, size_t in_len, unsigned char *out) {

    EVP_CIPHER_CTX *ctx;
    const unsigned char *iv = in;
    const unsigned char *ct = in + IV_SIZE;
    int ct_len = (int)(in_len - IV_SIZE - TAG_SIZE);
    unsigned char *tag = (unsigned char *)(in + in_len - TAG_SIZE);
    int len, pt_len, ret = -1;

    if (in_len < IV_SIZE + TAG_SIZE) return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;
    if (EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) != 1) goto out;
    pt_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) goto out;
    /* fails when tag does not authenticate ciphertext */
    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) goto out;
    ret = pt_len + len;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void to_hex(const unsigned char *in, size_t len, char *out) {
    static const char a[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[2 * i]     = a[in[i] >> 4];
        out[2 * i + 1] = a[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int from_hex(const char *in, unsigned char *out, size_t len) {
    size_t i;
    int hi, lo;
    for (i = 0; i < len; i++) {
        hi = hex_val(in[2 * i]);
        lo = hex_val(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}
