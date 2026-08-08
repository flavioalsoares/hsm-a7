/* fw/include/drbg.h -- CTR_DRBG com AES-256, NIST SP 800-90A secao 10.2
 *
 * FRONTEIRA: dentro, e fundo. O estado do DRBG (Key e V) e material de
 * chave: quem o conhece preve toda saida futura, e portanto toda chave que
 * o HSM gerar a partir dele. Nao existe, e nao pode passar a existir,
 * caminho que exponha esse estado -- nem para depuracao.
 *
 * ---------------------------------------------------------------------
 * POR QUE UM DRBG, SE JA HA UM TRNG
 *
 * A fonte fisica e lenta, tem vies residual e nao tem vazao previsivel.
 * O DRBG resolve os tres: recebe entropia de verdade uma vez (a semente),
 * e a partir dela produz saida em velocidade de AES, com propriedades
 * demonstraveis.
 *
 * A troca de garantias e o ponto: a saida deixa de ser imprevisivel "por
 * fisica" e passa a ser imprevisivel "porque quebrar AES-256 e inviavel".
 * Isso e desejavel -- fisica e dificil de medir, AES nao.
 *
 * ---------------------------------------------------------------------
 * O QUE E O ESTADO, E POR QUE SAO DOIS CAMPOS
 *
 *   Key  256 bits    chave AES usada para gerar
 *   V    128 bits    contador, incrementado antes de CADA bloco
 *
 * Gerar e literalmente AES-CTR: V = V+1, saida = AES(Key, V). O que
 * transforma isso num DRBG e o UPDATE, que roda depois de cada geracao e
 * troca Key e V por material novo derivado deles mesmos.
 *
 * O update e o que da BACKTRACKING RESISTANCE: quem capturar o estado
 * agora nao consegue reconstruir a saida ja entregue, porque a Key que a
 * produziu foi sobrescrita e nao e recuperavel a partir da atual.
 *
 * ---------------------------------------------------------------------
 * A FUNCAO DE DERIVACAO (df)
 *
 * A semente crua nao entra direto. Ela passa pelo Block_Cipher_df
 * (secao 10.3.2), que a comprime para exatamente seedlen = 384 bits
 * distribuindo a entropia por todo o bloco.
 *
 * Sem df, uma fonte que entregue 256 bits com entropia concentrada nos
 * primeiros bytes semearia um estado parcialmente previsivel. Com df, a
 * entropia se espalha. E o motivo de os vetores do CAVP virem em duas
 * familias, "use df" e "no df": sao algoritmos diferentes e um nao passa
 * nos vetores do outro. Aqui e USE DF.
 *
 * ---------------------------------------------------------------------
 * RESEED
 *
 * A norma exige resemeadura antes de reseed_interval geracoes. O limite
 * teorico para CTR_DRBG e 2^48, absurdamente alto; este projeto usa um
 * numero MUITO menor, porque o custo aqui e baixo (a fonte esta no mesmo
 * die) e porque o valor didatico esta em ter a politica implementada e
 * visivel, nao em espremer vazao.
 */
#ifndef DRBG_H
#define DRBG_H

#include <stdint.h>

#define DRBG_KEYLEN    32u                        /* AES-256 */
#define DRBG_OUTLEN    16u                        /* bloco AES */
#define DRBG_SEEDLEN   (DRBG_KEYLEN + DRBG_OUTLEN) /* 48 bytes = 384 bits */

/* Entropia minima para semear, em bytes. A norma pede security_strength
 * bits de entropia; com AES-256 sao 256 bits. */
#define DRBG_ENTROPIA_MIN  32u

/* Gerações antes de exigir resemeadura. Ver o cabecalho. */
#define DRBG_RESEED_INTERVALO  1024u

typedef struct {
    uint8_t  key[DRBG_KEYLEN];
    uint8_t  v[DRBG_OUTLEN];
    uint32_t reseed_contador;
    int      instanciado;
} drbg_estado_t;

/* Instancia a partir de material bruto (SP 800-90A 10.2.1.3.2).
 *
 * 'nonce' e 'personalizacao' podem ser NULL/0. O nonce existe para que
 * duas instancias com a MESMA entropia -- por exemplo dois dispositivos
 * com uma fonte defeituosa igual -- ainda divirjam.
 *
 * Devolve 0 em sucesso. */
int drbg_instantiate(drbg_estado_t *st,
                     const uint8_t *entropia, uint32_t entropia_n,
                     const uint8_t *nonce, uint32_t nonce_n,
                     const uint8_t *personalizacao, uint32_t pers_n);

/* Resemeia com entropia nova (10.2.1.4.2). */
int drbg_reseed(drbg_estado_t *st,
                const uint8_t *entropia, uint32_t entropia_n,
                const uint8_t *adicional, uint32_t adicional_n);

/* Gera n bytes (10.2.1.5.2). 'adicional' pode ser NULL/0.
 *
 * Devolve 0 em sucesso, -1 em erro, e -2 se a resemeadura for exigida --
 * neste caso NAO gera nada. Devolver bytes e sinalizar "eu deveria ter
 * resemeado" seria inutil: quem chamou ja usou os bytes. */
int drbg_generate(drbg_estado_t *st, uint8_t *saida, uint32_t n,
                  const uint8_t *adicional, uint32_t adicional_n);

/* Zeroiza o estado. Depois disto o DRBG volta a nao estar instanciado. */
void drbg_uninstantiate(drbg_estado_t *st);

/* ---------------------------------------------------------------------
 * DRBG do dispositivo
 *
 * Uma instancia global, semeada pelo TRNG. E o unico caminho por onde sai
 * aleatoriedade para o host (comando RANDOM). A fonte bruta NUNCA sai.
 * ------------------------------------------------------------------- */

/* Semeia a instancia global a partir do TRNG. Devolve 0 em sucesso. */
int drbg_dispositivo_semear(void);

/* Bytes para uso do HSM e para o comando RANDOM. Resemeia sozinho quando o
 * intervalo estoura. Devolve 0 em sucesso. */
int drbg_dispositivo_bytes(uint8_t *saida, uint32_t n);

#endif /* DRBG_H */
