/* fw/include/pinverif.h -- verificacao de PIN: offset e PVV (fase 8, etapa 8.5)
 *
 * As contas dos dois metodos que NAO dependem de chave: decimalizar, somar e
 * subtrair o offset, montar o dado de entrada do PVV e extrair o PVV. A cifra
 * (um bloco de 3DES sob a chave de verificacao) fica em keystore.c, que e o
 * unico lugar onde o PIN e a chave existem.
 *
 * O mesmo arquivo e compilado no PC por host/test_pinverif.py, e comparado
 * com host/pinverif.py. Mexer num exige mexer no outro.
 *
 * METODO DO OFFSET (o metodo do caixa eletronico dos anos 1970):
 *
 *   natural = decimaliza( 3DES_PVK( dados de validacao ) )   16 digitos
 *   PIN     = natural + offset      digito a digito, modulo 10
 *   offset  = PIN - natural         idem
 *
 *   Vale para os `n` primeiros digitos, `n` = tamanho do PIN, de 4 a 12.
 *   A tabela de decimalizacao leva cada digito hexadecimal a um decimal.
 *
 * PVV:
 *
 *   TSP = 11 digitos do PAN (os da direita, sem o verificador)
 *         . indice da chave (1 digito) . 4 primeiros digitos do PIN
 *   C   = 3DES_PVK( TSP )                 TSP lido como 16 digitos BCD
 *   PVV = os 4 primeiros digitos decimais de C, da esquerda para a direita;
 *         se faltar, completa com as letras de C, na ordem, A->0 ... F->5.
 *
 * ⚠ TUDO AQUI E SEGREDO: o PIN natural e tao bom quanto o PIN (o offset e
 * publico), e o resultado da cifra do PVV tambem. As funcoes escolhem por
 * mascara e nao desviam pelo valor de nenhum deles. Os digitos trafegam como
 * VALORES de 0 a 9, um por byte, e nao como caracteres.
 */
#ifndef PINVERIF_H
#define PINVERIF_H

#include <stdint.h>

#define PINV_TABELA     16u   /* tabela de decimalizacao: 16 digitos ASCII */
#define PINV_DADOS      8u    /* dados de validacao: um bloco de DES       */
#define PINV_NATURAL    16u   /* digitos que a decimalizacao produz        */
#define PINV_PVV        4u
#define PINV_PVV_PAN    12u   /* o PVV pede pelo menos 12 digitos de PAN   */

/* 1 se `tab` sao 16 caracteres de '0' a '9'. A tabela e dado publico; se ela
 * e AUTORIZADA quem decide e o MAC, em keystore.c. */
int pinv_tabela_forma(const uint8_t tab[PINV_TABELA]);

/* `cifrado` (8 bytes, 16 digitos hexadecimais) -> 16 digitos decimais, pelo
 * que a tabela manda. FRONTEIRA: dentro; `natural` e segredo. */
void pinv_decimaliza(const uint8_t cifrado[PINV_DADOS],
                     const uint8_t tab[PINV_TABELA],
                     uint8_t natural[PINV_NATURAL]);

/* offset[i] = (pin[i] - natural[i]) mod 10, para i < n. */
void pinv_offset(const uint8_t *pin, const uint8_t *natural, uint32_t n,
                 uint8_t *offset);

/* 1 se (natural[i] + offset[i]) mod 10 == pin[i] para todo i < n. Tempo
 * constante no valor dos digitos. */
int pinv_offset_confere(const uint8_t *pin, const uint8_t *natural,
                        const uint8_t *offset, uint32_t n);

/* Monta o TSP. `pan` em ASCII, `pan_n` de 12 a 19; `indice` de 0 a 9; `pin4`
 * sao os quatro primeiros digitos do PIN, em valores. Devolve 0, ou -1 se o
 * PAN ou o indice nao servem. FRONTEIRA: dentro; `tsp` leva o PIN. */
int pinv_pvv_tsp(const uint8_t *pan, uint32_t pan_n, uint8_t indice,
                 const uint8_t pin4[4], uint8_t tsp[PINV_DADOS]);

/* `cifrado` -> os quatro digitos do PVV, em valores. Sem desvio pelo
 * conteudo. */
void pinv_pvv_extrai(const uint8_t cifrado[PINV_DADOS],
                     uint8_t pvv[PINV_PVV]);

#endif /* PINVERIF_H */
