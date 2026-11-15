/* fw/include/pkcs8.h -- chave privada RSA e de curva eliptica em PKCS#8
 *
 * E o conteudo do key block de uma chave assimetrica (decisao do usuario,
 * 2026-11-14): em vez de um layout proprio, a codificacao publica que as
 * bibliotecas e o openssl entendem.
 *
 *   PKCS#8  PrivateKeyInfo, RFC 5958 (so a versao 0, sem atributos)
 *   RSA     RSAPrivateKey, RFC 8017 A.1.2 (dois primos)
 *   curva   ECPrivateKey, RFC 5915, com a curva P-256 no AlgorithmIdentifier
 *
 * Tudo em DER: comprimento definido e na forma mais curta. O leitor recusa
 * o que nao for exatamente isso -- nao ha BER, nem campo opcional ignorado.
 *
 * ⚠ A norma do key block (X9.143) e paga, e este projeto nao confirmou que
 * e esta a codificacao que ela manda usar para chave assimetrica. O PKCS#8
 * e um formato publico e bem documentado; nao e alegacao de conformidade.
 *
 * FRONTEIRA: dentro. Entrada e saida destas funcoes sao chave privada em
 * claro. Elas nao guardam nada; quem chama apaga os buffers.
 *
 * Aqui so ha bytes: nenhuma conta usa o coprocessador, e por isso o arquivo
 * roda tambem no PC (host/test_pkcs8.py).
 */
#ifndef PKCS8_H
#define PKCS8_H

#include <stdint.h>

/* Formato interno, o que rsa.c e ecc.c usam:
 *   RSA    e(4) p q dp dq qinv, 128 bytes cada         644 bytes
 *   curva  d(32) Qx(32) Qy(32)                          96 bytes */
#define PKCS8_RSA_INTERNA  644u
#define PKCS8_EC_INTERNA   96u

/* Teto do DER: RSA-2048 com todo inteiro no tamanho maximo, e P-256 com a
 * chave publica. */
#define PKCS8_RSA_MAX      1222u
#define PKCS8_EC_MAX       138u

/* RSA: monta o DER. `n` e o modulo (p*q, 256 bytes, de quem ja o calculou).
 * O expoente privado `d`, que o PKCS#8 exige e o formato interno nao tem, e
 * calculado aqui: d = e^-1 mod (p-1)(q-1). Devolve 0 e o tamanho em
 * `der_n`; -1 se nao couber em `max`, se `n` nao for p*q, ou se `e` nao
 * tiver inverso. */
int pkcs8_rsa_monta(const uint8_t chave[PKCS8_RSA_INTERNA],
                    const uint8_t n[256],
                    uint8_t *der, uint32_t max, uint32_t *der_n);

/* RSA: le o DER para o formato interno. Exige modulo de 2048 bits e primos
 * de 1024 bits, e `e` impar de ate 32 bits. `n` e `d` do DER sao lidos e
 * descartados: o equipamento recalcula n = p*q e verifica toda assinatura
 * com `e` antes de entrega-la. Devolve 0, ou -1 se o DER for recusado. */
int pkcs8_rsa_le(const uint8_t *der, uint32_t der_n,
                 uint8_t chave[PKCS8_RSA_INTERNA]);

/* Curva P-256: monta o DER, com a chave publica. */
int pkcs8_ec_monta(const uint8_t chave[PKCS8_EC_INTERNA],
                   uint8_t *der, uint32_t max, uint32_t *der_n);

/* Curva P-256: le o DER. A chave publica e opcional no formato: `tem_q`
 * recebe 1 se ela veio, e 0 se quem chama tem de calcula-la (Q = d*G). */
int pkcs8_ec_le(const uint8_t *der, uint32_t der_n,
                uint8_t chave[PKCS8_EC_INTERNA], int *tem_q);

#endif /* PKCS8_H */
