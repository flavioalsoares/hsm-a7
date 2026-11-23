/* fw/include/aes128.h -- AES-128, em software (fase 8, etapa 8.8b)
 *
 * So para o DUKPT AES (X9.24-3). O coprocessador faz so AES-256; o DUKPT AES
 * tambem usa BDK e chave de trabalho AES-128 (decisao do usuario,
 * 2026-11-22). Nenhum outro codigo usa este motor: dado, MAC, key block e
 * PIN block formato 4 com chave AES-256 continuam no coprocessador.
 *
 * FIPS 197. O NEORV32 nao tem cache, entao a consulta a caixa S nao cria o
 * canal de tempo que criaria num processador com cache (o mesmo argumento
 * do des.c).
 *
 * FRONTEIRA: dentro. `aes128_ctx_t` guarda as subchaves, que sao material de
 * chave. Quem o usa o apaga com aes128_apaga() em todo caminho.
 *
 * A referencia independente e a biblioteca `cryptography`, no PC
 * (host/test_dukpt.py), e os vetores ECB*128 do CAVP no autoteste de
 * primeiro uso (dukpt_aes_selftest()).
 */
#ifndef AES128_H
#define AES128_H

#include <stdint.h>

#define AES128_BLOCO  16u
#define AES128_CHAVE  16u

/* 11 subchaves de 16 bytes. */
typedef struct {
    uint8_t rk[11][16];
} aes128_ctx_t;

/* O contexto comum: 176 bytes de `static`. Um fio de execucao so; cada uso
 * termina com aes128_apaga(). */
aes128_ctx_t *aes128_ctx_comum(void);

/* Calcula as subchaves. Devolve 0, ou -1 com ponteiro nulo. FRONTEIRA: dentro. */
int  aes128_prepara(aes128_ctx_t *ctx, const uint8_t chave[AES128_CHAVE]);

/* Um bloco. `entrada` e `saida` podem ser o mesmo buffer. */
void aes128_bloco(const aes128_ctx_t *ctx, const uint8_t entrada[AES128_BLOCO],
                  uint8_t saida[AES128_BLOCO], int cifrar);

void aes128_apaga(aes128_ctx_t *ctx);

#endif /* AES128_H */
