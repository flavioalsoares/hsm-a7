/* fw/include/cvv.h -- CVV, CVV2 e iCVV (fase 8, etapa 8.6)
 *
 * As contas do codigo de verificacao de cartao que NAO dependem de chave:
 * montar os dois blocos de entrada e extrair os 3 digitos. A cifra fica em
 * keystore.c, que e o unico lugar onde a chave existe.
 *
 * O mesmo arquivo e compilado no PC por host/test_cvv.py, e comparado com
 * host/cvv.py. Mexer num exige mexer no outro.
 *
 * METODO (o mesmo para os tres codigos; so muda o codigo de servico):
 *
 *   D       = PAN . validade (4) . codigo de servico (3), completado com
 *             '0' a direita ate 32 digitos, lido como 16 bytes BCD
 *   X       = DES_A( D[0..7] ) xor D[8..15]      A = metade esquerda da CVK
 *   C       = 3DES_AB( X )                       a CVK inteira, dupla
 *   CVV     = os 3 primeiros digitos decimais de C, da esquerda para a
 *             direita; se faltar, completa com as letras de C, na ordem,
 *             A->0 ... F->5. E a mesma extracao do PVV, com 3 digitos.
 *
 *   CVV  (tarja):   o codigo de servico da tarja (ex.: 101, 201)
 *   CVV2 (verso):   000
 *   iCVV (chip):    999
 *
 * ⚠ O resultado da cifra e segredo ate virar CVV, e o CVV2 e dado sensivel
 * de autenticacao: a extracao escolhe por mascara e nao desvia pelo valor.
 * Os digitos trafegam como VALORES de 0 a 9, um por byte.
 */
#ifndef CVV_H
#define CVV_H

#include <stdint.h>

#define CVV_DIGITOS    3u
#define CVV_DADOS      16u   /* dois blocos de DES                        */
#define CVV_VALIDADE   4u
#define CVV_SERVICO    3u
#define CVV_PAN_MIN    12u
#define CVV_PAN_MAX    19u   /* 19 + 4 + 3 = 26 digitos, cabem nos 32     */

/* Monta D. `pan`, `validade` e `servico` sao caracteres ASCII.
 * Devolve 0, ou -1 se o PAN tiver menos de 12 ou mais de 19 digitos, ou se
 * algum campo tiver caractere que nao e digito. */
int  cvv_dados(const uint8_t *pan, uint32_t pan_n,
               const uint8_t validade[CVV_VALIDADE],
               const uint8_t servico[CVV_SERVICO],
               uint8_t dados[CVV_DADOS]);

/* C (8 bytes) -> os 3 digitos, em valores de 0 a 9. Sempre as mesmas 64
 * voltas. FRONTEIRA: dentro; `cifrado` e segredo. */
void cvv_extrai(const uint8_t cifrado[8], uint8_t cvv[CVV_DIGITOS]);

#endif /* CVV_H */
