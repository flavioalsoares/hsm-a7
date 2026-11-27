/* fw/include/emv.h -- ARQC e ARPC do EMV, 3DES (fase 8, etapa 8.10)
 *
 * O lado do EMISSOR. O chip do cartao calcula o ARQC com a chave dele (a
 * MK); o HSM do emissor refaz a MK a partir da chave mestra do emissor (a
 * IMK), confere o ARQC e calcula o ARPC, a resposta que o chip confere.
 *
 *     IMK --Opcao A--> MK do cartao --CSK (ATC)--> chave de sessao
 *                          |
 *                  esquema MK (CVN 10): a MK direto
 *
 *     ARQC  = retail MAC (ISO/IEC 9797-1 alg. 3) da chave, sobre os dados
 *     ARPC1 = 3DES da chave sobre ARQC xor (ARC || 000000000000)   8 bytes
 *     ARPC2 = retail MAC da chave sobre ARQC || CSU || dado proprio,
 *             preenchimento 2                                       4 bytes
 *
 * Fontes publicas: EMV Book 2, anexo A1 (Opcao A, A1.4.1; chave de sessao
 * comum, A1.3; ARPC, A1.2). A chave do ARPC e a mesma que conferiu o ARQC.
 *
 * FRONTEIRA: dentro. Recebe a IMK em claro e devolve chaves em claro. So
 * keystore.c chama estas funcoes: a IMK so existe em claro dentro do key
 * store. Um segundo chamador e sinal de que a pergunta certa e "por que este
 * codigo tem a IMK?". Nao ha funcao que gere ARQC: isso e do chip. As contas
 * do criptograma e do ARPC sao as mesmas, e o nome diz o que o HSM faz.
 *
 * Usa o contexto comum de 3DES (tdes_ctx_comum()) e o apaga antes de voltar.
 * Compila no PC, onde host/test_emv.py o confere contra os valores de
 * terceiros e contra host/emv.py. O algoritmo esta escrito duas vezes: aqui
 * e em host/emv.py. Mexer num exige mexer no outro.
 */
#ifndef EMV_H
#define EMV_H

#include <stdint.h>

#define EMV_CHAVE     16u   /* 3DES duplo: IMK, MK e chave de sessao */
#define EMV_AC_LEN     8u   /* ARQC */
#define EMV_ARPC1_LEN  8u
#define EMV_ARPC2_LEN  4u
#define EMV_ARC_LEN    2u
#define EMV_CSU_LEN    4u
#define EMV_PAD_AUT_MAX 8u  /* dado proprio do emissor no ARPC 2 */
#define EMV_PAN_MAX   19u

#define EMV_ESQ_MK    0     /* CVN 10: o criptograma sai da MK */
#define EMV_ESQ_CSK   1     /* chave de sessao comum, R = ATC || 000000000000 */

/* A MK do cartao pela Opcao A: os 16 digitos da direita de PAN || PSN
 * (completados com zeros a esquerda) em BCD, cifrados sob a IMK, e o mesmo
 * bloco invertido; paridade impar. `pan` sao `pan_n` digitos ASCII (1 a 19),
 * `psn` 2 digitos ASCII. Quem limita o PAN a 16 digitos (a Opcao A da
 * especificacao) e keystore.c. Devolve 0, ou -1 se a entrada nao e digito. */
int emv_mk_opcao_a(const uint8_t imk[EMV_CHAVE], const uint8_t *pan,
                   uint32_t pan_n, const uint8_t psn[2],
                   uint8_t mk[EMV_CHAVE]);

/* A chave de sessao comum: R com F0 e com 0F no terceiro byte, cifrados sob
 * a MK; paridade impar. */
int emv_csk(const uint8_t mk[EMV_CHAVE], const uint8_t r[8],
            uint8_t sk[EMV_CHAVE]);

/* A chave do criptograma e do ARPC: a MK (EMV_ESQ_MK) ou a chave de sessao
 * do ATC (EMV_ESQ_CSK). Devolve 0, ou -1. */
int emv_chave_ac(const uint8_t imk[EMV_CHAVE], const uint8_t *pan,
                 uint32_t pan_n, const uint8_t psn[2], const uint8_t atc[2],
                 int esquema, uint8_t chave[EMV_CHAVE]);

/* O criptograma (ARQC, TC ou AAC): retail MAC de 8 bytes, preenchimento 1
 * (zeros) ou 2 (80 e zeros). `n` > 0. Devolve 0, ou -1. */
int emv_criptograma(const uint8_t chave[EMV_CHAVE], const uint8_t *dados,
                    uint32_t n, uint8_t pad, uint8_t ac[EMV_AC_LEN]);

int emv_arpc1(const uint8_t chave[EMV_CHAVE], const uint8_t arqc[EMV_AC_LEN],
              const uint8_t arc[EMV_ARC_LEN], uint8_t arpc[EMV_ARPC1_LEN]);

/* `pad_aut_n` de 0 a 8. */
int emv_arpc2(const uint8_t chave[EMV_CHAVE], const uint8_t arqc[EMV_AC_LEN],
              const uint8_t csu[EMV_CSU_LEN], const uint8_t *pad_aut,
              uint32_t pad_aut_n, uint8_t arpc[EMV_ARPC2_LEN]);

/* Autoteste: um caso CVN 10 (MK, ARPC 1) e um CVN 18 (CSK, ARPC 2), de
 * fontes diferentes (vectors/emv/arqc.rsp, pelo mkkat.py). Parte do KAT do
 * 3DES. Devolve 0, ou -1. */
int emv_selftest(void);

#endif /* EMV_H */
