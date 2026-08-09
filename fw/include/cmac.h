/* fw/include/cmac.h -- AES-CMAC, NIST SP 800-38B
 *
 * FRONTEIRA: dentro. Recebe chave em claro.
 *
 * ---------------------------------------------------------------------
 * POR QUE O CMAC É A PEÇA CENTRAL DA FASE 3
 *
 * Ele faz duas coisas diferentes, e é a mesma função nas duas:
 *
 *   1. DERIVA KBEK e KBAK a partir da LMK, por propósito. Uma LMK, duas
 *      chaves filhas que não se confundem: `CMAC(LMK, "…ENC…")` e
 *      `CMAC(LMK, "…MAC…")`. Se as duas fossem iguais — ou derivadas de um
 *      jeito que permitisse trocar uma pela outra — o atacante usaria a
 *      chave de autenticação para cifrar, que é uma violação de separação
 *      de chaves e é o modo de falha clássico de HSM.
 *
 *   2. AUTENTICA o key block: CMAC sobre o header **mais** o corpo. É por
 *      isso que um byte trocado no header em ASCII invalida o bloco
 *      inteiro. Sem isso, um atacante edita "exportabilidade: não" para
 *      "sim" num blob que ele nem consegue decifrar.
 *
 * ---------------------------------------------------------------------
 * POR QUE NÃO CBC-MAC PURO
 *
 * CBC-MAC com IV zero é seguro só para mensagens de tamanho FIXO. Com
 * tamanho variável ele quebra: dado MAC(m), dá para construir uma mensagem
 * de duas partes cujo MAC é previsível, sem conhecer a chave. Os dois
 * subkeys do CMAC (K1 e K2) existem exatamente para fechar isso, e a
 * escolha entre eles é o que distingue mensagem alinhada ao bloco de
 * mensagem que precisou de padding.
 *
 * Um "MAC" caseiro que é só CBC-MAC parece funcionar em todo teste que se
 * escreve sem má-fé.
 */
#ifndef CMAC_H
#define CMAC_H

#include <stdint.h>

#define CMAC_KEY_LEN  32u   /* AES-256, e só — igual ao resto do projeto */
#define CMAC_TAG_LEN  16u

/* CMAC de uma mensagem inteira na memória.
 *
 * 'msg' pode ser NULL se msg_n for 0 — a mensagem vazia é um caso legítimo
 * e tem MAC definido, e os vetores do CAVP a incluem.
 *
 * Devolve 0 em sucesso. Em falha zeroiza 'tag'. */
int cmac_aes256(const uint8_t chave[CMAC_KEY_LEN],
                const uint8_t *msg, uint32_t msg_n,
                uint8_t tag[CMAC_TAG_LEN]);

/* Verificação em tempo constante.
 *
 * Devolve 1 se confere, 0 se não. Comparar MAC com memcmp é um canal
 * lateral: o tempo de retorno conta quantos bytes bateram, e com isso um
 * atacante forja tag byte a byte em 16·256 tentativas em vez de 2^128. */
int cmac_aes256_verifica(const uint8_t chave[CMAC_KEY_LEN],
                         const uint8_t *msg, uint32_t msg_n,
                         const uint8_t tag[CMAC_TAG_LEN]);

#endif /* CMAC_H */
