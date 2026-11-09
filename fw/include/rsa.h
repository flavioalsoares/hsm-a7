/* fw/include/rsa.h -- RSA-2048 sobre o produto de Montgomery (fase 7)
 *
 * FRONTEIRA: dentro. O hardware calcula um produto por comando, em
 * rtl/crypto/rsa_mont.v; este modulo dirige a exponenciacao.
 *
 * Numeros em big-endian. A chave privada esta no layout do key block
 * (TR31_RSA_CHAVE em tr31.h): e(4) p q dp dq qinv, 128 bytes cada.
 */
#ifndef RSA_H
#define RSA_H

#include <stdint.h>

#define RSA_BYTES        256u
#define RSA_SHA256_LEN   32u
#define RSA_CHAVE_PRIV   644u
#define RSA_E_PADRAO     65537u

/* out = s^e mod n. Devolve -1 se n, e ou s forem invalidos: n precisa ter
 * 2048 bits e ser impar, e impar e >= 3, e s < n. */
int rsa_publica(const uint8_t n[RSA_BYTES], uint32_t e,
                const uint8_t s[RSA_BYTES], uint8_t out[RSA_BYTES]);

/* Assinatura PKCS#1 v1.5 com SHA-256, sobre um digest ja calculado.
 * Devolve 1 valida, 0 invalida, -1 parametro invalido. */
int rsa_verifica(const uint8_t n[RSA_BYTES], uint32_t e,
                 const uint8_t digest[RSA_SHA256_LEN],
                 const uint8_t s[RSA_BYTES]);

/* Assinatura PKCS#1 v1.5 com SHA-256, por CRT em tempo constante.
 *
 * FRONTEIRA: dentro -- recebe a chave privada em claro. Verifica a
 * assinatura com e antes de devolve-la. Devolve 0 se assinou, -1 se a
 * chave e invalida, -2 se a verificacao reprovou (falha de calculo: nada
 * sai). Apaga o coprocessador ao terminar, em qualquer caminho. */
int rsa_crt_assina(const uint8_t chave[RSA_CHAVE_PRIV],
                   const uint8_t digest[RSA_SHA256_LEN],
                   uint8_t sig[RSA_BYTES]);

/* Gera um par de 2048 bits, e = 65537 (FIPS 186-5, A.1.3). `chave` sai no
 * layout do key block; `n`, o modulo publico. Leva segundos.
 *
 * FRONTEIRA: dentro. Devolve 0, ou -1 sem chave nenhuma (tudo apagado). */
int rsa_gera(uint8_t chave[RSA_CHAVE_PRIV], uint8_t n[RSA_BYTES]);

/* Miller-Rabin com as rodadas da geracao (FIPS 186-5 B.3.1), sobre w de
 * 1024 bits, impar, com o bit alto ligado. 1 provavelmente primo, 0
 * composto, -1 falha. Existe separado para o KAT do CAVP. */
int rsa_primo_provavel(const uint8_t w[RSA_BYTES / 2u]);

#endif
