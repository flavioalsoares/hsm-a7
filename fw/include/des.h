/* fw/include/des.h -- DES e 3DES (TDEA), em software (fase 8)
 *
 * ⚠ LEGADO. O DES simples esta quebrado por busca exaustiva, e o 3DES nao e
 * mais aceito pelo NIST para cifrar dados novos. Estao aqui porque a rede de
 * pagamento ainda os usa: PIN blocks, verificacao de PIN, CVV, DUKPT TDES. A
 * LMK e o coprocessador continuam AES-256. Ver o manual, Parte VII.
 *
 *   DES    bloco de 8 bytes, chave de 8 bytes (56 bits uteis e 8 de
 *          paridade), 16 rodadas de Feistel. FIPS 46-3.
 *   3DES   C = E_K3( D_K2( E_K1(P) ) ). SP 800-67.
 *          chave tripla: 24 bytes. Chave dupla: 16 bytes, com K3 = K1.
 *
 * O motor e em C, e nao no coprocessador: decisao do usuario (2026-11-14).
 * O NEORV32 nao tem cache, entao a consulta as caixas S nao cria o canal de
 * tempo que criaria num processador com cache.
 *
 * FRONTEIRA: dentro. `tdes_ctx_t` guarda as subchaves, que sao material de
 * chave. Quem a declara a apaga com tdes_apaga() em todo caminho.
 *
 * O algoritmo esta escrito duas vezes: aqui e em host/des.py.
 */
#ifndef DES_H
#define DES_H

#include <stdint.h>

#define DES_BLOCO      8u
#define DES_CHAVE      8u
#define TDES_CHAVE_2   16u
#define TDES_CHAVE_3   24u

/* 16 subchaves de 48 bits, 6 bytes cada, para cada uma das tres chaves. */
typedef struct {
    uint8_t ks[3][16][6];
} tdes_ctx_t;

/* O contexto comum do firmware. Um contexto tem 288 bytes, e a DMEM e
 * curta: quem precisa de 3DES usa este, em vez de declarar o seu. O firmware
 * tem um fio de execucao so, e cada uso termina com tdes_apaga(). */
tdes_ctx_t *tdes_ctx_comum(void);

/* Calcula as subchaves. `n` e 16 (chave dupla) ou 24 (tripla).
 * Devolve 0, ou -1 se `n` for outro valor. Nao confere paridade. */
int  tdes_prepara(tdes_ctx_t *ctx, const uint8_t *chave, uint32_t n);

/* Um bloco. `entrada` e `saida` podem ser o mesmo buffer. */
void tdes_bloco(const tdes_ctx_t *ctx, const uint8_t entrada[DES_BLOCO],
                uint8_t saida[DES_BLOCO], int cifrar);

/* CBC. `n` tem de ser multiplo de 8. `entrada` e `saida` podem ser o mesmo
 * buffer. Devolve 0, ou -1 se `n` nao for multiplo de 8. */
int  tdes_cbc(const tdes_ctx_t *ctx, const uint8_t iv[DES_BLOCO],
              const uint8_t *entrada, uint8_t *saida, uint32_t n, int cifrar);

/* Apaga as subchaves. */
void tdes_apaga(tdes_ctx_t *ctx);

/* Paridade impar: o bit baixo de cada byte de uma chave DES. A cifra nao usa
 * esse bit; a norma o define para detectar chave corrompida.
 * `des_paridade_ajusta()` acerta o bit; `des_paridade_ok()` devolve 1 se
 * todos os bytes tem paridade impar. */
void des_paridade_ajusta(uint8_t *chave, uint32_t n);
int  des_paridade_ok(const uint8_t *chave, uint32_t n);

/* 1 se a chave 3DES nao deve ser usada (SP 800-67): alguma das partes e uma
 * chave fraca ou semifraca do DES, ou K1 = K2, ou K2 = K3, ou, na chave
 * tripla, K1 = K3. A comparacao ignora os bits de paridade. `n` e 16 ou 24.
 * Quem gera chave sorteia de novo quando isto devolve 1. */
int  tdes_chave_ruim(const uint8_t *chave, uint32_t n);

#endif /* DES_H */
