/* fw/include/keystore.h -- key store em BRAM
 *
 * FRONTEIRA: dentro, e é o bloco mais sensível do firmware. Aqui moram as
 * chaves em claro.
 *
 * ---------------------------------------------------------------------
 * ONDE AS CHAVES FICAM, E POR QUE ISSO SATISFAZ A REGRA 2
 *
 * Os slots são variáveis estáticas, então vivem na DMEM do NEORV32 — que é
 * inferida em **Block RAM** do FPGA (8 KB, `rtl/soc/neorv32_wrapper.vhd`).
 * A regra 2 do CLAUDE.md diz "chaves só em BRAM": está satisfeita por
 * construção, não por promessa.
 *
 * O que a regra proíbe também está ausente por construção: não há DDR3 no
 * design (XBUS desligado), e não há caminho do firmware para a SPI flash.
 *
 * ---------------------------------------------------------------------
 * O CAMPO QUE MAIS IMPORTA É O QUE NÃO É CHAVE
 *
 * Modelar os campos do header X9.143 **desde o início** não é preparação
 * para depois: é o que faz `exportability` significar alguma coisa. Uma
 * chave marcada `'N'` não pode sair, **por nenhum caminho** — e a única
 * forma de garantir isso é existir um único ponto de saída que consulte o
 * campo.
 *
 * Por isso a API abaixo é assimétrica de propósito:
 *
 *   keystore_usa_aes()      carrega a chave no coprocessador e NÃO a
 *                           devolve. É por onde toda operação passa.
 *
 *   keystore_exporta()      devolve os bytes. É a ÚNICA função que faz
 *                           isso, checa `exportability`, e existe só para
 *                           a camada de key block.
 *
 * Duas portas, uma trancada. Se houvesse um `keystore_get_key()` genérico,
 * a checagem viraria convenção — e convenção é o que se esquece no
 * caminho raro.
 *
 * ---------------------------------------------------------------------
 * ESTADO DO DISPOSITIVO
 *
 * Este módulo **não** consulta a máquina de estados. Quem decide se um
 * comando pode rodar é a tabela de comandos (`fw/src/cmd.c`), com a
 * máscara de estados. Misturar as duas coisas daria dois lugares para
 * verificar a mesma condição, e dois lugares divergem.
 */
#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <stdint.h>

#define KS_N_SLOTS      16u
#define KS_KEY_MAX      32u   /* AES-256, e só */
#define KS_KCV_LEN       3u

/* Handle de slot. ZERO É INVÁLIDO, de propósito: um handle não
 * inicializado, ou um campo de payload esquecido em zero, não pode cair
 * por acidente no slot 0. Os válidos vão de 1 a KS_N_SLOTS. */
typedef uint8_t ks_handle_t;
#define KS_HANDLE_INVALIDO  0u

/* Campos do header X9.143, em ASCII como na norma.
 *
 * Guardados como os bytes do padrão e não como enum: é o header que vai
 * para o key block, contado no MAC. Converter de enum para ASCII na hora
 * de exportar seria uma tradução a mais para errar. */
#define KS_USO_BDK      "B0"   /* Base Derivation Key   */
#define KS_USO_KEK      "K0"   /* Key Encryption Key    */
#define KS_USO_DADOS    "D0"   /* chave de dados        */
#define KS_USO_MAC      "M0"   /* chave de MAC          */

#define KS_ALG_AES      'A'
#define KS_ALG_3DES     'T'    /* aceito no header, NÃO implementado aqui */

#define KS_MODO_CIFRA   'E'
#define KS_MODO_DECIFRA 'D'
#define KS_MODO_AMBOS   'B'
#define KS_MODO_NENHUM  'N'

#define KS_EXP_SIM      'E'    /* exportável sob KEK        */
#define KS_EXP_NAO      'N'    /* nunca sai, em hipótese nenhuma */
#define KS_EXP_SENSIVEL 'S'    /* sensível: sai só sob regra mais estrita */

/* Metadados de um slot -- tudo menos a chave.
 *
 * Existe separado para que consultar um slot NÃO devolva material de
 * chave. `keystore_info()` preenche isto; não há como pedir "o slot
 * inteiro". */
typedef struct {
    uint8_t  em_uso;
    uint8_t  uso[2];
    uint8_t  algoritmo;
    uint8_t  modo;
    uint8_t  exportabilidade;
    uint8_t  key_len;
    uint8_t  kcv[KS_KCV_LEN];
    uint32_t contador_uso;
} ks_info_t;

/* Zeroiza tudo -- slots e LMK. Chamado no boot e pelo comando ZEROIZE.
 *
 * Apaga também a chave expandida do coprocessador: ela é material de
 * chave e vive FORA da DMEM, no fabric. Zeroizar só a memória do
 * firmware deixaria a última chave usada viva no `aes_key_mem`. */
void keystore_init(void);

/* PROVA da zeroização: 1 se não sobrou um byte diferente de zero em
 * nenhuma região de chave -- slots, padding das structs, LMK e KCV.
 *
 * Existe porque "chamei a função de apagar" não é a mesma coisa que
 * "apagou". Um `wipe()` que o compilador tivesse eliminado, um campo novo
 * que ninguém acrescentou ao laço, um slot fora do intervalo: os três
 * falham em silêncio, e os três aparecem aqui.
 *
 * Consulta pura -- não apaga nada. Quem apaga é `keystore_zeroiza_tudo()`. */
int keystore_prova_zeroizacao(void);

/* Apaga e CONFERE. Devolve 0 se, depois de apagar, a prova passou.
 *
 * É por aqui que o comando ZEROIZE passa: um zeroize que reporta sucesso
 * sem ter apagado é pior que um que falha, porque o operador acredita
 * nele e devolve o dispositivo achando que está limpo. */
int keystore_zeroiza_tudo(void);

/* Instala uma chave num slot livre.
 *
 * `chave` é material em claro; o chamador zeroiza a origem. O KCV é
 * calculado aqui e guardado.
 *
 * Devolve o handle, ou KS_HANDLE_INVALIDO se não houver slot livre, se os
 * campos do header forem inválidos, ou se o hardware falhar. */
ks_handle_t keystore_instala(const uint8_t uso[2], uint8_t algoritmo,
                             uint8_t modo, uint8_t exportabilidade,
                             const uint8_t *chave, uint8_t key_len);

/* Apaga um slot. Sobrescreve a chave com barreira; não é só marcar livre.
 * Devolve 0 em sucesso. */
int keystore_apaga(ks_handle_t h);

/* Metadados. NÃO devolve chave. Devolve 0 em sucesso. */
int keystore_info(ks_handle_t h, ks_info_t *out);

/* Quantos slots estão livres.
 *
 * Não é segredo — `KEY_INFO` já permite contar a ocupação handle a
 * handle. Existe para que "não instalou" possa dizer **por quê**: header
 * inválido é erro de quem pediu, store cheio é estado do dispositivo, e
 * juntar os dois num código só deixa o operador sem saber o que fazer.
 *
 * ⚠ Não confundir com "o último slot está ocupado". Os slots são
 * alocados no primeiro livre, então apagar um do meio deixa buraco: o
 * último pode estar ocupado com o store longe de cheio. */
uint8_t keystore_livres(void);

/* Carrega a chave do slot no coprocessador e incrementa o contador de uso.
 *
 * NÃO devolve os bytes -- é por aqui que toda operação criptográfica passa.
 * `precisa_modo` é KS_MODO_CIFRA ou KS_MODO_DECIFRA; a função recusa se o
 * `modo` do slot não permitir.
 *
 * Devolve 0 em sucesso. */
int keystore_usa_aes(ks_handle_t h, uint8_t precisa_modo);

/* ÚNICO caminho que devolve material de chave.
 *
 * Recusa se `exportabilidade` for KS_EXP_NAO. Existe para a camada de key
 * block (fase 3) e para mais nada. Se aparecer um segundo chamador, a
 * pergunta certa não é "como faço isso funcionar" -- é "por que este código
 * precisa da chave em claro?".
 *
 * Devolve o comprimento em bytes, ou 0 se recusado. */
uint8_t keystore_exporta(ks_handle_t h, uint8_t out[KS_KEY_MAX]);

/* ---------------------------------------------------------------------
 * LMK -- região separada dos slots
 *
 * Separada porque ela não é uma chave como as outras: não tem handle, não
 * é exportável por caminho nenhum, e é ela que protege as demais. Um
 * `keystore_apaga()` que pudesse alcançá-la por índice seria um bug de uma
 * linha com consequência total.
 * ------------------------------------------------------------------- */

/* Quantos componentes formam a LMK.
 *
 * Três é a prática usual, e a razão é operacional, não criptográfica: dois
 * custodiantes não dão margem nenhuma se um faltar no dia, e mais de três
 * transforma a cerimônia em logística. O XOR não fica mais forte com mais
 * partes -- ele já é perfeito com duas. */
#define KS_LMK_N_COMPONENTES  3u

/* Acumula um componente por XOR. Split knowledge: cada custodiante carrega
 * o seu e não vê os demais, e nenhum componente isolado revela nada.
 *
 * `n` é o índice do componente (0, 1, 2), só para o firmware saber quantos
 * já entraram. Devolve 0 em sucesso. */
int lmk_componente(uint8_t n, const uint8_t comp[KS_KEY_MAX]);

/* Quantos componentes já entraram. */
uint8_t lmk_componentes_carregados(void);

/* 1 se a LMK está completa (três componentes). */
int lmk_completa(void);

/* KCV da LMK. É o ÚNICO dado derivado dela que sai da fronteira -- e sai
 * porque três bytes não permitem recuperar 256 bits, e porque sem ele o
 * operador não teria como conferir que carregou a chave certa.
 *
 * Devolve 0 em sucesso. */
int lmk_kcv(uint8_t out[KS_KCV_LEN]);

/* Carrega a LMK no coprocessador. Não devolve bytes, como os slots. */
int lmk_usa_aes(void);

/* Deriva as subchaves de key block (KBEK e KBAK) a partir da LMK, **sem
 * devolver a LMK**.
 *
 * É a terceira porta deste módulo, e ela existe justamente para que não
 * seja preciso abrir a primeira. A camada de key block precisa de duas
 * chaves derivadas da chave mestra; se a única forma de obtê-las fosse
 * pedir a LMK, `lmk_exporta()` teria de existir — e a partir daí a
 * promessa "a LMK não sai daqui" vira convenção.
 *
 * O que sai são chaves DERIVADAS por CMAC, e a derivação não é
 * inversível: quem tiver KBEK e KBAK não consegue voltar à LMK. É a
 * mesma assimetria de `keystore_usa_aes()`, num degrau acima.
 *
 * O chamador zeroiza as duas com `wipe()`. Devolve 0 em sucesso. */
int lmk_deriva_kb(uint8_t kbek[KS_KEY_MAX], uint8_t kbak[KS_KEY_MAX]);

/* Zeroiza a LMK e todos os slots -- as chaves derivadas não sobrevivem à
 * chave que as protege. */
void lmk_zeroiza(void);

/* ---------------------------------------------------------------------
 * KCV -- Key Check Value
 *
 * Três bytes mais significativos de AES-ECB da chave sobre um bloco de
 * zeros. Serve para o operador conferir que carregou a chave certa sem
 * nunca ver a chave.
 *
 * Por que TRÊS bytes, e não mais: é uma troca deliberada. Mais bytes
 * verificam melhor e vazam mais -- o KCV é um oráculo de verificação de
 * chave, e um KCV longo o bastante permitiria busca. Três bytes dão 1 em
 * 16 milhões de colisão, que basta para pegar erro de digitação e não
 * basta para atacar.
 * ------------------------------------------------------------------- */
int keystore_kcv(const uint8_t *chave, uint8_t key_len, uint8_t out[KS_KCV_LEN]);

#endif /* KEYSTORE_H */
