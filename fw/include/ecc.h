/* fw/include/ecc.h -- ECDSA sobre a curva P-256 (fase 7)
 *
 * FRONTEIRA: dentro. Os produtos modulares sao do coprocessador de
 * Montgomery (rtl/crypto/rsa_mont.v), com 256 bits; este modulo dirige a
 * multiplicacao de ponto e as contas da assinatura.
 *
 * Numeros em big-endian, 32 bytes. A chave privada esta no layout do key
 * block (TR31_EC_CHAVE em tr31.h): d || Qx || Qy. A chave publica e
 * Qx || Qy e a assinatura e r || s.
 */
#ifndef ECC_H
#define ECC_H

#include <stdint.h>

#define EC_BYTES        32u
#define EC_PUB          64u     /* Qx || Qy */
#define EC_SIG          64u     /* r || s */
#define EC_CHAVE_PRIV   96u     /* d || Qx || Qy */

/* Verifica a assinatura sobre um digest ja calculado (FIPS 186-5, 6.4.2).
 * Valida a chave publica antes: coordenadas menores que p e ponto na
 * curva. Devolve 1 valida, 0 invalida, -1 parametro invalido (chave
 * publica recusada, ou falha do coprocessador). */
int ecdsa_verifica(const uint8_t q[EC_PUB], const uint8_t digest[EC_BYTES],
                   const uint8_t sig[EC_SIG]);

/* Assina um digest (FIPS 186-5, 6.4.1). O numero secreto por mensagem sai
 * do DRBG, por amostragem com rejeicao (A.3.2).
 *
 * FRONTEIRA: dentro -- recebe a chave privada em claro. Verifica a
 * assinatura com Q antes de devolve-la. Devolve 0 se assinou, -1 se a
 * chave e invalida, -2 se a verificacao reprovou (falha de calculo: nada
 * sai). Apaga o coprocessador ao terminar, em qualquer caminho. */
int ecdsa_assina(const uint8_t chave[EC_CHAVE_PRIV],
                 const uint8_t digest[EC_BYTES], uint8_t sig[EC_SIG]);

/* A assinatura com o numero secreto k dado por quem chama. Existe separada
 * para o KAT do CAVP, que fixa k. NUNCA chamar com k que nao seja o do
 * vetor: k repetido ou previsivel entrega a chave privada. Nao verifica a
 * assinatura. Devolve 0, ou -1 (d ou k fora de [1, n-1], r ou s zero). */
int ecdsa_assina_k(const uint8_t d[EC_BYTES], const uint8_t digest[EC_BYTES],
                   const uint8_t k[EC_BYTES], uint8_t sig[EC_SIG]);

/* Q = d * G. Devolve 0, ou -1 se d esta fora de [1, n-1].
 *
 * FRONTEIRA: dentro -- d e chave privada. */
int ec_publica(const uint8_t d[EC_BYTES], uint8_t q[EC_PUB]);

/* Gera um par (FIPS 186-5, A.2.2: amostragem com rejeicao). `chave` sai no
 * layout do key block.
 *
 * FRONTEIRA: dentro. Devolve 0, ou -1 sem chave nenhuma (tudo apagado). */
int ecdsa_gera(uint8_t chave[EC_CHAVE_PRIV]);

#endif
