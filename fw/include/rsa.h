/* fw/include/rsa.h -- RSA-2048 sobre o produto de Montgomery (fase 7)
 *
 * FRONTEIRA: dentro. O hardware calcula um produto por comando, em
 * rtl/crypto/rsa_mont.v; este modulo dirige a exponenciacao.
 *
 * Por enquanto so a operacao publica. Numeros em big-endian, 256 bytes.
 */
#ifndef RSA_H
#define RSA_H

#include <stdint.h>

#define RSA_BYTES        256u
#define RSA_SHA256_LEN   32u

/* out = s^e mod n. Devolve -1 se n, e ou s forem invalidos: n precisa ter
 * 2048 bits e ser impar, e impar e >= 3, e s < n. */
int rsa_publica(const uint8_t n[RSA_BYTES], uint32_t e,
                const uint8_t s[RSA_BYTES], uint8_t out[RSA_BYTES]);

/* Assinatura PKCS#1 v1.5 com SHA-256, sobre um digest ja calculado.
 * Devolve 1 valida, 0 invalida, -1 parametro invalido. */
int rsa_verifica(const uint8_t n[RSA_BYTES], uint32_t e,
                 const uint8_t digest[RSA_SHA256_LEN],
                 const uint8_t s[RSA_BYTES]);

#endif
