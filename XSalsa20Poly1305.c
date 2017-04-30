#include "XSalsa20Poly1305.h"
#include <sodium.h>
#include <glib.h>

int decrypt_string_xs(const char *key, const char *str, char *dest, int len) {
    if (!key || !key[0])
        return 0;
    gsize out_len;
    guchar * nonce_ciphertext;
    /* base64 decode the message */
    nonce_ciphertext = g_base64_decode(str, &out_len);
    int MESSAGE_LEN = out_len-(crypto_secretbox_NONCEBYTES+crypto_secretbox_MACBYTES);
    int CIPHERTEXT_LEN = crypto_secretbox_MACBYTES + MESSAGE_LEN;
    /* split it into nonce and ciphertext again */
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[CIPHERTEXT_LEN];
    memcpy(nonce, nonce_ciphertext, crypto_secretbox_NONCEBYTES);
    memcpy(ciphertext, nonce_ciphertext + crypto_secretbox_NONCEBYTES, CIPHERTEXT_LEN);
    g_free(nonce_ciphertext);
    /* decrypt the message */
    if (crypto_secretbox_open_easy((unsigned char*)dest, ciphertext, CIPHERTEXT_LEN, nonce, (unsigned char*)key) != 0) {
        /* cannot decrypt */
        return 1;
    }
    return 0;
}

int encrypt_string_xs(const char *key, const char *str, char *dest, int len) {
    if (!key || !key[0])
        return 0;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[crypto_secretbox_MACBYTES+len];
    /* choosing a random nonce */
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    /* encrypt the message */
    crypto_secretbox_easy(ciphertext, (const unsigned char*)str, len, nonce, (const unsigned char*)key);
    /* put nonce and ciphertext together */
    guchar nonce_ciphertext[crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES];
    memcpy(nonce_ciphertext, nonce, crypto_secretbox_NONCEBYTES);
    memcpy(nonce_ciphertext+crypto_secretbox_NONCEBYTES, ciphertext, crypto_secretbox_MACBYTES + len);
    /* and base64 encode it */
    gchar * encoded_str;
    encoded_str = g_base64_encode(nonce_ciphertext, crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES);
    strncpy(dest, encoded_str, ((crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES + 2) / 3 * 4) + 1);
    /* clean up a bit (maybe not needed) */
    sodium_memzero(nonce_ciphertext, crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES);
    sodium_memzero(ciphertext, crypto_secretbox_MACBYTES+len);
    sodium_memzero(nonce, crypto_secretbox_NONCEBYTES);
    /* sodium_memzero encoded_str? */
    g_free(encoded_str);
    return 1;
}

void encrypt_key_xs(const char *key, char *encryptedKey) {
}
