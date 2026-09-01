/* fw/include/aes_modos.h -- modos de operacao do AES
 *
 * FRONTEIRA: dentro. Mas repare no que NAO esta na assinatura.
 *
 * ---------------------------------------------------------------------
 * A FUNCAO NAO RECEBE CHAVE, E ISSO E O PROJETO
 *
 * `aes_cbc()` opera sobre a chave que JA ESTA carregada no coprocessador.
 * Nao ha parametro de chave, entao nao ha como esta funcao ver material
 * de chave, nem como ela vazar por um buffer esquecido.
 *
 * Quem carrega a chave e quem tem direito a ela:
 *
 *   keystore_usa_aes()   carrega a chave de um SLOT, e checa o `modo` do
 *                        slot antes -- uma chave marcada 'E' recusa
 *                        decifrar. E o unico caminho para os comandos de
 *                        operacao.
 *
 *   hsm_cfs_aes_key()    carrega bytes crus. So quem ja tem os bytes
 *                        legitimamente na mao chama isto -- hoje o
 *                        tr31.c, com as subchaves derivadas da LMK.
 *
 * A consequencia pratica: acrescentar um comando de cifrar dados NAO
 * abre caminho novo para chave. O comando pede ao key store que carregue,
 * e o key store decide. A separacao de uso vive num lugar so.
 *
 * ---------------------------------------------------------------------
 * POR QUE CBC E NAO ECB
 *
 * O hardware faz ECB de um bloco; encadeamento e daqui (hsm_cfs.h). Mas
 * expor ECB para dados seria ensinar o erro que a Parte III do manual usa
 * como exemplo: blocos iguais viram criptogramas iguais, e a estrutura do
 * texto claro atravessa a cifra intacta.
 *
 * O IV e explicito e vem de quem chama. Nao e gerado aqui pelo mesmo
 * motivo que o enchimento do key block nao e: uma funcao que puxa
 * entropia por conta propria e impossivel de testar de forma
 * deterministica.
 */
#ifndef AES_MODOS_H
#define AES_MODOS_H

#include <stdint.h>

#define AES_BLOCO  16u

/* AES-CBC sobre a chave JA CARREGADA no coprocessador.
 *
 * `n` tem de ser multiplo de AES_BLOCO -- o chamador garante. Um CBC que
 * "tratasse" tamanho invalido em silencio processaria lixo.
 *
 * `entrada` e `saida` podem ser o mesmo buffer.
 *
 * Devolve 0 em sucesso. */
int aes_cbc(const uint8_t iv[AES_BLOCO],
            const uint8_t *entrada, uint8_t *saida, uint32_t n, int cifrar);

#endif /* AES_MODOS_H */
