/* fw/include/mont.h -- o coprocessador de Montgomery visto do firmware
 *
 * FRONTEIRA: dentro. O hardware (rtl/crypto/rsa_mont.v) calcula um produto
 * por comando: dst = a * b * R^-1 mod m. Aqui ficam o preparo do modulo e
 * a exponenciacao em tempo constante, usados pelo RSA e pelo ECDSA.
 */
#ifndef MONT_H
#define MONT_H

#include <stdint.h>

/* Endereco de janela de um registrador, e o do modulo. */
#define J_REG(r) ((uint16_t)((r) << 7))
#define J_MOD   0x400u

/* Registradores do core. R_R2 e R_UM sao de mont_prepara(); R_BASE, R_X e
 * R_Y, de mont_escada(). */
#define R_BASE  0u
#define R_ACC   1u
#define R_R2    2u
#define R_UM    3u
#define R_X     4u
#define R_Y     5u
#define R_T     6u

/* Programa o modulo m (n bytes, big-endian, bit alto ligado, impar) e
 * deixa R^2 mod m em R_R2 e 1 em R_UM, com R = 2^(8n). `x` e rascunho de
 * n bytes. Devolve 0, ou -1 se o core nao respondeu. */
int mont_prepara(const uint8_t *m, uint32_t n, uint8_t *x);

/* Escada de Montgomery: R_X = base^d * R mod m. A base, em forma normal,
 * esta em R_BASE. TEMPO CONSTANTE: um produto e um quadrado por bit de d,
 * zeros a esquerda inclusive. Devolve 0, ou -1 se o core nao respondeu. */
int mont_escada(const uint8_t *d, uint32_t n);

#endif
