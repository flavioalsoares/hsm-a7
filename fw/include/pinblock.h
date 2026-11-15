/* fw/include/pinblock.h -- PIN block ISO 9564-1, formatos 0 e 4 (fase 8)
 *
 * So a FORMA do bloco: montar o campo do PAN e conferir o campo do PIN.
 * Nenhuma funcao daqui ve chave. Quem cifra e decifra e o key store
 * (keystore_pin_abre / keystore_pin_fecha), que e o unico lugar onde o
 * campo do PIN existe em claro.
 *
 *   campo do PIN (16 bytes):
 *       nibble 0      4            (controle: formato 4)
 *       nibble 1      tamanho do PIN, 4 a 12
 *       nibbles 2-15  o PIN em BCD, e depois o enchimento A
 *       bytes 8-15    aleatorios
 *
 *   campo do PAN (16 bytes):
 *       nibble 0      tamanho do PAN menos 12 (0 se tem 12 ou menos)
 *       nibbles 1-19  o PAN em BCD; com menos de 12 digitos, zeros a
 *                     esquerda ate 12; o resto do campo e zero
 *
 *   bloco = AES( AES(campo do PIN) XOR campo do PAN )
 *
 * FORMATO 0 (3DES, bloco de 8 bytes):
 *
 *   campo do PIN (8 bytes):
 *       nibble 0      0            (controle: formato 0)
 *       nibble 1      tamanho do PIN, 4 a 12
 *       nibbles 2-15  o PIN em BCD, e depois o enchimento F
 *
 *   campo do PAN (8 bytes):
 *       nibbles 0-3   zero
 *       nibbles 4-15  os 12 digitos do PAN a direita, SEM o ultimo (o
 *                     digito verificador). O PAN tem de 13 a 19 digitos.
 *
 *   bloco = 3DES( campo do PIN XOR campo do PAN )
 *
 * Dentro do key store o PIN fica sempre na forma do campo do formato 4.
 * As duas funcoes de conversao daqui levam de uma forma a outra.
 *
 * O formato esta escrito duas vezes: aqui e em host/pinblock.py.
 */
#ifndef PINBLOCK_H
#define PINBLOCK_H

#include <stdint.h>

#define PIN_BLOCO      16u
#define PIN_MIN        4u
#define PIN_MAX        12u
#define PIN_PAN_MAX    19u
#define PIN_FORMATO_4  '4'
#define PIN_FORMATO_0  '0'
#define PIN_BLOCO_0    8u
#define PIN_PAN0_MIN   13u

/* Monta o campo do PAN a partir dos digitos ASCII. O PAN e dado publico.
 * Devolve 0, ou -1 se `n` nao esta em 1..19 ou ha caractere que nao e
 * digito. */
int pinblock_campo_pan(const uint8_t *pan, uint32_t n,
                       uint8_t campo[PIN_BLOCO]);

/* 1 se `campo` e um campo de PIN formato 4 bem formado: controle 4,
 * tamanho de 4 a 12, digitos de 0 a 9 e enchimento A.
 *
 * FRONTEIRA: dentro. `campo` e o PIN em claro. A funcao nao desvia pelo
 * valor de nenhum nibble: acumula as diferencas e decide no fim. */
int pinblock_campo_valido(const uint8_t campo[PIN_BLOCO]);

/* Monta o campo do PAN do formato 0. Devolve 0, ou -1 se `n` nao esta em
 * 13..19 ou ha caractere que nao e digito. O PAN e dado publico. */
int pinblock_campo_pan0(const uint8_t *pan, uint32_t n,
                        uint8_t campo[PIN_BLOCO_0]);

/* Confere um campo de PIN formato 0 (controle 0, tamanho de 4 a 12, digitos
 * de 0 a 9, enchimento F) e escreve o mesmo PIN na forma do formato 4, com
 * os bytes 8 a 15 em zero. Devolve 1 se o campo e bem formado; se nao e,
 * `campo4` nao deve ser usado.
 *
 * FRONTEIRA: dentro. Os dois campos sao o PIN em claro. Sem desvio pelo
 * valor de nenhum nibble. */
int pinblock_f0_para_f4(const uint8_t campo0[PIN_BLOCO_0],
                        uint8_t campo4[PIN_BLOCO]);

/* O caminho de volta: de um campo formato 4 JA CONFERIDO para o campo do
 * formato 0. Os 8 bytes aleatorios do formato 4 nao entram.
 *
 * FRONTEIRA: dentro. */
void pinblock_f4_para_f0(const uint8_t campo4[PIN_BLOCO],
                         uint8_t campo0[PIN_BLOCO_0]);

#endif /* PINBLOCK_H */
