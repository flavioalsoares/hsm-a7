/* fw/include/tr31.h -- key block ANSI X9.143 (TR-31 versao D)
 *
 * FRONTEIRA: dentro. Este modulo ve chave em claro dos dois lados --
 * a chave que esta sendo embrulhada e as subchaves que a protegem.
 *
 * Ele e a razao de a fase 3 existir. Ate aqui o dispositivo guardava
 * chave; a partir daqui ele sabe deixar chave SAIR sem que ela vaze, que
 * e um problema diferente e mais dificil.
 *
 * ---------------------------------------------------------------------
 * O FORMATO
 *
 *     cabecalho(16 ASCII) || hex(corpo cifrado) || hex(MAC de 16 bytes)
 *
 *     D 0144 D0 A B 00 E 00 00
 *     | |    |  | | |  | |  +-- reservado, "00"
 *     | |    |  | | |  | +----- blocos opcionais, "00"
 *     | |    |  | | |  +------- exportabilidade: E, N ou S
 *     | |    |  | | +---------- versao da chave, "00"
 *     | |    |  | +------------ modo de uso: E, D, B, N
 *     | |    |  +-------------- algoritmo: 'A' = AES
 *     | |    +----------------- uso: D0, K0, M0, B0, P0
 *     | +---------------------- comprimento TOTAL, 4 digitos ASCII
 *     +------------------------ versao do formato: 'D'
 *
 * Corpo em claro, antes de cifrar:
 *
 *     comprimento em BITS (2 bytes, big-endian) || chave || enchimento
 *
 * O enchimento leva o corpo a multiplo de 16 e e ALEATORIO. Nao e
 * decoracao: sem ele o tamanho do bloco denunciaria o tamanho da chave.
 *
 * ---------------------------------------------------------------------
 * AS TRES DECISOES QUE O FORMATO TOMA, E QUE VALE ENTENDER ANTES DE MEXER
 *
 * 1. DUAS SUBCHAVES, NAO UMA. KBEK cifra o corpo, KBAK autentica. Saem da
 *    mesma KBPK por CMAC, com um campo de PROPOSITO diferente na entrada.
 *    Se fossem a mesma, um oraculo de MAC seria um oraculo de cifragem de
 *    graca. E a mesma separacao que o keystore aplica ao recusar decifrar
 *    com chave marcada 'E'.
 *
 * 2. O CABECALHO ENTRA NO MAC. Sao 16 bytes de ASCII legivel -- e
 *    autenticados. Sem isso, um atacante que nao consegue decifrar o
 *    corpo edita `exportabilidade` de 'N' para 'E', ou o modo de 'D' para
 *    'B', e devolve o bloco. O criptograma nao muda; a POLITICA muda.
 *    Chave protegida sob metadado desprotegido nao esta protegida.
 *
 * 3. O MAC E O IV DO CBC. Nao ha IV para transmitir, e dois blocos com a
 *    mesma chave nunca coincidem se um bit do cabecalho diferir. E
 *    MAC-then-encrypt sobre o texto CLARO, que e o que permite recusar um
 *    bloco adulterado antes de acreditar no que decifrou.
 *
 * ---------------------------------------------------------------------
 * POR QUE AS FUNCOES RECEBEM KBEK E KBAK, E NAO A KBPK
 *
 * Porque a KBPK deste dispositivo e a LMK, e a LMK nao sai do keystore --
 * `keystore.h` nao tem funcao que a devolva, de proposito. Quem for
 * embrulhar sob a LMK deriva as subchaves por dentro do keystore e passa
 * SO ELAS para ca.
 *
 * `tr31_deriva()` existe para o caso em que a KBPK esta legitimamente em
 * maos -- hoje, so o KAT, que traz uma KBPK de teste. Se aparecer um
 * segundo chamador dela no firmware, a pergunta certa nao e "como faco
 * isso compilar": e "por que este codigo tem a chave mestra?".
 *
 * ---------------------------------------------------------------------
 * A OUTRA IMPLEMENTACAO
 *
 * `host/tr31.py` faz o mesmo formato, em Python, sobre uma biblioteca de
 * terceiros. As duas foram escritas para DISCORDAR: qualquer diferenca de
 * leitura da norma aparece como MAC invalido, que e barulhento e
 * imediato. Se as duas compartilhassem o AES, elas concordariam sobre um
 * erro no AES sem nunca discordar.
 */
#ifndef TR31_H
#define TR31_H

#include <stdint.h>

#define TR31_CAB_LEN       16u
#define TR31_MAC_LEN       16u
#define TR31_BLOCO         16u
#define TR31_SUBCHAVE_LEN  32u   /* KBEK e KBAK: AES-256, como a LMK */

/* Maior chave que este dispositivo embrulha. AES-256, e so -- igual ao
 * resto do projeto. */
#define TR31_CHAVE_MAX     32u

/* Corpo em claro: 2 bytes de comprimento + chave, arredondado para cima
 * ao bloco do AES. Para 32 bytes de chave: 34 -> 48. */
#define TR31_CORPO_MAX     48u

/* Maior bloco em ASCII. NAO inclui terminador. */
#define TR31_ASCII_MAX     (TR31_CAB_LEN + 2u * TR31_CORPO_MAX + 2u * TR31_MAC_LEN)

/* Cabecalho decomposto. Os campos sao os BYTES ASCII da norma, nao enums:
 * e o cabecalho que vai para o MAC, e traduzir de enum para ASCII na hora
 * de serializar seria uma conversao a mais para errar. Mesma decisao de
 * keystore.h, e as duas estruturas usam os mesmos KS_USO_*, KS_ALG_*,
 * KS_MODO_* e KS_EXP_*. */
typedef struct {
    uint8_t uso[2];
    uint8_t algoritmo;
    uint8_t modo;
    uint8_t versao_chave[2];
    uint8_t exportabilidade;
} tr31_cab_t;

/* KBEK e KBAK a partir de uma KBPK. Ver acima por que quase ninguem deve
 * chamar isto. Devolve 0 em sucesso. */
int tr31_deriva(const uint8_t kbpk[TR31_SUBCHAVE_LEN],
                uint8_t kbek[TR31_SUBCHAVE_LEN],
                uint8_t kbak[TR31_SUBCHAVE_LEN]);

/* Embrulha. `saida` recebe TR31_ASCII_MAX bytes no maximo, SEM
 * terminador; `saida_n` recebe quantos foram escritos.
 *
 * `enchimento` sao os bytes de preenchimento do corpo. Nao sao gerados
 * aqui de proposito: quem chama e que sabe se o aleatorio vem do DRBG do
 * dispositivo ou de um vetor de teste, e uma funcao de formato que puxa
 * entropia por conta propria e uma funcao impossivel de testar de forma
 * deterministica. Precisa de (16 - (2 + chave_n) % 16) % 16 bytes.
 *
 * Devolve 0 em sucesso. Em FALHA, `saida` fica indefinido -- o cabecalho
 * ja pode ter sido escrito la -- e `*saida_n` nao e tocado. Nao ha
 * vazamento nisso (o cabecalho e publico), mas quem chamar tem de olhar o
 * retorno antes de olhar o buffer: meio bloco parece um bloco. */
int tr31_embrulha(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                  const uint8_t kbak[TR31_SUBCHAVE_LEN],
                  const tr31_cab_t *cab,
                  const uint8_t *chave, uint8_t chave_n,
                  const uint8_t *enchimento, uint8_t enchimento_n,
                  char *saida, uint32_t *saida_n);

/* Desembrulha e AUTENTICA. `chave` recebe no maximo TR31_CHAVE_MAX bytes.
 *
 * Devolve 0 se o bloco e integro; -1 em qualquer outro caso, e em falha
 * zeroiza `chave` e `cab`.
 *
 * UM codigo de erro so, de proposito. Distinguir "MAC invalido" de
 * "enchimento invalido" ajuda a depurar e e exatamente o oraculo de
 * padding: o atacante nao precisa da chave, precisa so que o dispositivo
 * diga em qual etapa parou. */
int tr31_desembrulha(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                     const uint8_t kbak[TR31_SUBCHAVE_LEN],
                     const char *bloco, uint32_t bloco_n,
                     tr31_cab_t *cab,
                     uint8_t chave[TR31_CHAVE_MAX], uint8_t *chave_n);

/* Teste de funcao critica para o POST. Devolve 0 se passou. */
int tr31_selftest(void);

#endif /* TR31_H */
