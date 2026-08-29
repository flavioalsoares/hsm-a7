/* fw/src/tr31.c -- key block ANSI X9.143 (TR-31 versao D)
 *
 * FRONTEIRA: dentro. Ver o cabecalho de tr31.h para o formato e para as
 * tres decisoes que ele toma.
 *
 * O AES vem do coprocessador, como em todo o resto do firmware. CBC e
 * encadeamento, e encadeamento e daqui -- o hardware faz um bloco ECB de
 * cada vez (hsm_cfs.h).
 */
#include "tr31.h"
#include "cmac.h"
#include "hsm_cfs.h"
#include "kat_vectors.h"
#include "keystore.h"
#include "wipe.h"

#define BLK  TR31_BLOCO

/* Propositos da derivacao (X9.143). Dois valores, dois papeis -- e a
 * unica coisa que separa a chave que cifra da chave que autentica. */
#define DERIV_KBEK  0x0000u
#define DERIV_KBAK  0x0001u

/* Identificador de algoritmo na derivacao. So o AES-256 aparece aqui
 * porque so ele existe neste dispositivo; a norma tambem define 0x0002
 * (AES-128) e 0x0003 (AES-192), e o KAT usa uma KBPK de 256 bits. */
#define DERIV_ALG_AES256  0x0004u
#define DERIV_BITS_256    0x0100u

/* ---------------------------------------------------------------------
 * Utilitarios
 * ------------------------------------------------------------------- */
static void bloco_xor(uint8_t dst[BLK], const uint8_t src[BLK])
{
    uint32_t i;
    for (i = 0u; i < BLK; i++) {
        dst[i] ^= src[i];
    }
}

static char nibble_hex(uint8_t v)
{
    return (char)((v < 10u) ? (uint8_t)('0' + v) : (uint8_t)('A' + (v - 10u)));
}

/* -1 se nao for hexadecimal. Aceita so MAIUSCULAS mais os digitos:
 * a norma escreve o bloco em maiusculas, e aceitar minuscula abriria duas
 * codificacoes para o mesmo bloco -- com MACs diferentes, porque o
 * cabecalho entra no MAC como bytes. Duas grafias do "mesmo" bloco e o
 * comeco de um problema de canonicalizacao. */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'A' && c <= 'F') { return 10 + (c - 'A'); }
    return -1;
}

static void hex_escreve(char *dst, const uint8_t *src, uint32_t n)
{
    uint32_t i;
    for (i = 0u; i < n; i++) {
        dst[2u * i]      = nibble_hex((uint8_t)(src[i] >> 4));
        dst[2u * i + 1u] = nibble_hex((uint8_t)(src[i] & 0x0Fu));
    }
}

/* Devolve 0 em sucesso. `n` e o numero de BYTES de saida. */
static int hex_le(const char *src, uint8_t *dst, uint32_t n)
{
    uint32_t i;
    for (i = 0u; i < n; i++) {
        int alto  = hex_nibble(src[2u * i]);
        int baixo = hex_nibble(src[2u * i + 1u]);
        if (alto < 0 || baixo < 0) {
            return -1;
        }
        dst[i] = (uint8_t)((alto << 4) | baixo);
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * AES-CBC sobre o coprocessador
 *
 * Carrega a chave uma vez e encadeia. `n` e multiplo de BLK e o chamador
 * garante isso -- um CBC que "trata" tamanho invalido silenciosamente e
 * um CBC que processa lixo.
 * ------------------------------------------------------------------- */
static int cbc(const uint8_t chave[TR31_SUBCHAVE_LEN], const uint8_t iv[BLK],
               const uint8_t *entrada, uint8_t *saida, uint32_t n, int cifrar)
{
    uint8_t  encadeia[BLK], anterior[BLK], tmp[BLK];
    uint32_t i, j;
    int      r = 0;

    if (hsm_cfs_aes_key(chave) != 0) {
        return -1;
    }
    for (i = 0u; i < BLK; i++) {
        encadeia[i] = iv[i];
    }

    for (i = 0u; i < n; i += BLK) {
        if (cifrar) {
            for (j = 0u; j < BLK; j++) {
                tmp[j] = entrada[i + j];
            }
            bloco_xor(tmp, encadeia);
            if (hsm_cfs_aes_block(tmp, &saida[i], 1) != 0) {
                r = -1;
                goto fim;
            }
            for (j = 0u; j < BLK; j++) {
                encadeia[j] = saida[i + j];
            }
        } else {
            /* O criptograma deste bloco e o encadeamento do proximo, e
             * precisa ser guardado ANTES de decifrar: entrada e saida
             * podem ser o mesmo buffer. */
            for (j = 0u; j < BLK; j++) {
                anterior[j] = entrada[i + j];
            }
            if (hsm_cfs_aes_block(&entrada[i], tmp, 0) != 0) {
                r = -1;
                goto fim;
            }
            bloco_xor(tmp, encadeia);
            for (j = 0u; j < BLK; j++) {
                saida[i + j]  = tmp[j];
                encadeia[j]   = anterior[j];
            }
        }
    }

fim:
    wipe(encadeia, sizeof encadeia);
    wipe(anterior, sizeof anterior);
    wipe(tmp, sizeof tmp);
    return r;
}

/* ---------------------------------------------------------------------
 * Derivacao de KBEK e KBAK
 *
 * Cada bloco de 16 bytes de saida e um CMAC sobre 8 bytes:
 *
 *     contador(1) || proposito(2) || separador(1) || algoritmo(2) || bits(2)
 *
 * O contador e o que permite tirar 256 bits de uma primitiva que devolve
 * 128 -- duas chamadas com entradas diferentes. O campo de PROPOSITO e o
 * que impede KBEK e KBAK de serem a mesma coisa.
 * ------------------------------------------------------------------- */
static int deriva_uma(const uint8_t kbpk[TR31_SUBCHAVE_LEN], uint16_t proposito,
                      uint8_t saida[TR31_SUBCHAVE_LEN])
{
    uint8_t  dados[8];
    uint32_t contador;
    int      r = 0;

    for (contador = 1u; contador <= 2u; contador++) {
        dados[0] = (uint8_t)contador;
        dados[1] = (uint8_t)(proposito >> 8);
        dados[2] = (uint8_t)(proposito & 0xFFu);
        dados[3] = 0x00u;                                /* separador */
        dados[4] = (uint8_t)(DERIV_ALG_AES256 >> 8);
        dados[5] = (uint8_t)(DERIV_ALG_AES256 & 0xFFu);
        dados[6] = (uint8_t)(DERIV_BITS_256 >> 8);
        dados[7] = (uint8_t)(DERIV_BITS_256 & 0xFFu);

        if (cmac_aes256(kbpk, dados, sizeof dados,
                        &saida[(contador - 1u) * CMAC_TAG_LEN]) != 0) {
            r = -1;
            break;
        }
    }

    wipe(dados, sizeof dados);
    if (r != 0) {
        wipe(saida, TR31_SUBCHAVE_LEN);
    }
    return r;
}

int tr31_deriva(const uint8_t kbpk[TR31_SUBCHAVE_LEN],
                uint8_t kbek[TR31_SUBCHAVE_LEN],
                uint8_t kbak[TR31_SUBCHAVE_LEN])
{
    if (deriva_uma(kbpk, DERIV_KBEK, kbek) != 0) {
        return -1;
    }
    if (deriva_uma(kbpk, DERIV_KBAK, kbak) != 0) {
        wipe(kbek, TR31_SUBCHAVE_LEN);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * Cabecalho
 * ------------------------------------------------------------------- */
static int cab_valido(const tr31_cab_t *cab)
{
    if (cab->algoritmo != (uint8_t)KS_ALG_AES) {
        /* 'T' e valido na norma e NAO neste hardware. Aceitar o byte
         * seria produzir um bloco que promete 3DES a quem for importar. */
        return 0;
    }
    if (cab->modo != (uint8_t)KS_MODO_CIFRA &&
        cab->modo != (uint8_t)KS_MODO_DECIFRA &&
        cab->modo != (uint8_t)KS_MODO_AMBOS &&
        cab->modo != (uint8_t)KS_MODO_NENHUM) {
        return 0;
    }
    if (cab->exportabilidade != (uint8_t)KS_EXP_SIM &&
        cab->exportabilidade != (uint8_t)KS_EXP_NAO &&
        cab->exportabilidade != (uint8_t)KS_EXP_SENSIVEL) {
        return 0;
    }
    return 1;
}

static void cab_escreve(char *dst, const tr31_cab_t *cab, uint32_t total)
{
    dst[0]  = 'D';
    dst[1]  = (char)('0' + (total / 1000u) % 10u);
    dst[2]  = (char)('0' + (total / 100u) % 10u);
    dst[3]  = (char)('0' + (total / 10u) % 10u);
    dst[4]  = (char)('0' + total % 10u);
    dst[5]  = (char)cab->uso[0];
    dst[6]  = (char)cab->uso[1];
    dst[7]  = (char)cab->algoritmo;
    dst[8]  = (char)cab->modo;
    dst[9]  = (char)cab->versao_chave[0];
    dst[10] = (char)cab->versao_chave[1];
    dst[11] = (char)cab->exportabilidade;
    dst[12] = '0';   /* blocos opcionais: nenhum */
    dst[13] = '0';
    dst[14] = '0';   /* reservado */
    dst[15] = '0';
}

/* Devolve o comprimento declarado, ou 0 se o cabecalho nao serve. */
static uint32_t cab_le(const char *src, tr31_cab_t *cab)
{
    uint32_t total = 0u;
    uint32_t i;

    if (src[0] != 'D') {
        return 0u;   /* este projeto so faz a versao D */
    }
    for (i = 1u; i <= 4u; i++) {
        if (src[i] < '0' || src[i] > '9') {
            return 0u;
        }
        total = total * 10u + (uint32_t)(src[i] - '0');
    }

    cab->uso[0]          = (uint8_t)src[5];
    cab->uso[1]          = (uint8_t)src[6];
    cab->algoritmo       = (uint8_t)src[7];
    cab->modo            = (uint8_t)src[8];
    cab->versao_chave[0] = (uint8_t)src[9];
    cab->versao_chave[1] = (uint8_t)src[10];
    cab->exportabilidade = (uint8_t)src[11];

    /* Blocos opcionais nao sao suportados. Recusar e a resposta certa:
     * um bloco opcional que este firmware IGNORASSE ainda estaria no MAC,
     * entao o MAC fecharia e o dispositivo teria aceitado um campo que
     * nao entendeu -- que e como uma restricao de uso desaparece. */
    if (src[12] != '0' || src[13] != '0') {
        return 0u;
    }
    return total;
}

/* ---------------------------------------------------------------------
 * Embrulhar
 * ------------------------------------------------------------------- */
int tr31_embrulha(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                  const uint8_t kbak[TR31_SUBCHAVE_LEN],
                  const tr31_cab_t *cab,
                  const uint8_t *chave, uint8_t chave_n,
                  const uint8_t *enchimento, uint8_t enchimento_n,
                  char *saida, uint32_t *saida_n)
{
    uint8_t  corpo[TR31_CORPO_MAX];
    uint8_t  cifrado[TR31_CORPO_MAX];
    uint8_t  mac[TR31_MAC_LEN];
    uint8_t  autentica[TR31_CAB_LEN + TR31_CORPO_MAX];
    uint32_t corpo_n, falta, total, i;
    uint16_t bits;
    int      r = -1;

    if (chave_n == 0u || chave_n > TR31_CHAVE_MAX || !cab_valido(cab)) {
        return -1;
    }

    bits    = (uint16_t)(chave_n * 8u);
    corpo_n = 2u + (uint32_t)chave_n;
    falta   = ((BLK - (corpo_n % BLK)) % BLK);

    if (enchimento_n < falta) {
        return -1;
    }

    corpo[0] = (uint8_t)(bits >> 8);
    corpo[1] = (uint8_t)(bits & 0xFFu);
    for (i = 0u; i < chave_n; i++) {
        corpo[2u + i] = chave[i];
    }
    for (i = 0u; i < falta; i++) {
        corpo[corpo_n + i] = enchimento[i];
    }
    corpo_n += falta;

    total = TR31_CAB_LEN + 2u * corpo_n + 2u * TR31_MAC_LEN;
    cab_escreve(saida, cab, total);

    /* O MAC cobre cabecalho + corpo EM CLARO, e so depois vira IV.
     * Autenticar o criptograma daria um MAC que nao diz nada sobre a
     * chave que esta la dentro. */
    for (i = 0u; i < TR31_CAB_LEN; i++) {
        autentica[i] = (uint8_t)saida[i];
    }
    for (i = 0u; i < corpo_n; i++) {
        autentica[TR31_CAB_LEN + i] = corpo[i];
    }

    if (cmac_aes256(kbak, autentica, TR31_CAB_LEN + corpo_n, mac) != 0) {
        goto fim;
    }
    if (cbc(kbek, mac, corpo, cifrado, corpo_n, 1) != 0) {
        goto fim;
    }

    hex_escreve(&saida[TR31_CAB_LEN], cifrado, corpo_n);
    hex_escreve(&saida[TR31_CAB_LEN + 2u * corpo_n], mac, TR31_MAC_LEN);
    *saida_n = total;
    r = 0;

fim:
    wipe(corpo, sizeof corpo);
    wipe(autentica, sizeof autentica);
    wipe(cifrado, sizeof cifrado);
    wipe(mac, sizeof mac);
    return r;
}

/* ---------------------------------------------------------------------
 * Desembrulhar
 *
 * A ordem e a parte que importa: autentica ANTES de acreditar em
 * qualquer campo do texto decifrado, e devolve o MESMO erro em todos os
 * caminhos de recusa.
 * ------------------------------------------------------------------- */
int tr31_desembrulha(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                     const uint8_t kbak[TR31_SUBCHAVE_LEN],
                     const char *bloco, uint32_t bloco_n,
                     tr31_cab_t *cab,
                     uint8_t chave[TR31_CHAVE_MAX], uint8_t *chave_n)
{
    uint8_t  corpo[TR31_CORPO_MAX];
    uint8_t  mac[TR31_MAC_LEN];
    uint8_t  autentica[TR31_CAB_LEN + TR31_CORPO_MAX];
    uint32_t declarado, corpo_n, i;
    uint32_t bits;
    int      r = -1;

    *chave_n = 0u;

    if (bloco_n < TR31_CAB_LEN + 2u * BLK + 2u * TR31_MAC_LEN ||
        bloco_n > TR31_ASCII_MAX) {
        goto fim;
    }

    declarado = cab_le(bloco, cab);
    if (declarado != bloco_n) {
        /* O campo de comprimento entra no MAC, entao mentir nele ja
         * invalidaria o bloco -- conferir aqui e sobre nao decifrar o que
         * nem tem forma de bloco. */
        goto fim;
    }

    corpo_n = (bloco_n - TR31_CAB_LEN - 2u * TR31_MAC_LEN) / 2u;
    if (corpo_n == 0u || (corpo_n % BLK) != 0u || corpo_n > TR31_CORPO_MAX) {
        goto fim;
    }

    if (hex_le(&bloco[TR31_CAB_LEN], corpo, corpo_n) != 0) {
        goto fim;
    }
    if (hex_le(&bloco[bloco_n - 2u * TR31_MAC_LEN], mac, TR31_MAC_LEN) != 0) {
        goto fim;
    }

    /* corpo entra cifrado e sai em claro, no mesmo buffer. */
    if (cbc(kbek, mac, corpo, corpo, corpo_n, 0) != 0) {
        goto fim;
    }

    for (i = 0u; i < TR31_CAB_LEN; i++) {
        autentica[i] = (uint8_t)bloco[i];
    }
    for (i = 0u; i < corpo_n; i++) {
        autentica[TR31_CAB_LEN + i] = corpo[i];
    }

    /* Verificacao em tempo constante -- ver cmac.h. */
    if (cmac_aes256_verifica(kbak, autentica, TR31_CAB_LEN + corpo_n, mac) != 1) {
        goto fim;
    }

    /* So agora o conteudo decifrado merece credito. */
    bits = ((uint32_t)corpo[0] << 8) | (uint32_t)corpo[1];
    if ((bits % 8u) != 0u || bits == 0u) {
        goto fim;
    }
    if ((2u + bits / 8u) > corpo_n || (bits / 8u) > TR31_CHAVE_MAX) {
        goto fim;
    }
    if (!cab_valido(cab)) {
        goto fim;
    }

    *chave_n = (uint8_t)(bits / 8u);
    for (i = 0u; i < *chave_n; i++) {
        chave[i] = corpo[2u + i];
    }
    r = 0;

fim:
    wipe(corpo, sizeof corpo);
    wipe(autentica, sizeof autentica);
    wipe(mac, sizeof mac);
    if (r != 0) {
        wipe(chave, TR31_CHAVE_MAX);
        wipe(cab, sizeof *cab);
        *chave_n = 0u;
    }
    return r;
}

/* ---------------------------------------------------------------------
 * Teste de funcao critica -- POST
 *
 * Nao ha KAT do CAVP para FORMATO de key block: o CAVP valida algoritmo,
 * e X9.143 e formato. O vetor usado aqui e um valor conhecido de
 * terceiros, fixado por commit e hash em vectors/MANIFEST.txt, que
 * documenta exatamente o quanto ele vale.
 *
 * Tres verificacoes, e cada uma cobre uma falha diferente:
 *
 *   1. desembrulhar o vetor e achar a chave certa -- prova a derivacao, o
 *      CBC e o CMAC de uma vez, contra um numero que este projeto nao
 *      escolheu.
 *   2. um bit trocado no CABECALHO tem de ser recusado. E a propriedade
 *      que faz `exportabilidade` significar alguma coisa, e a unica que
 *      um erro de "esqueci de incluir o cabecalho no MAC" nao passa.
 *   3. ida e volta -- prova a direcao de EMBRULHAR, que nao tem KAT
 *      possivel porque o enchimento e aleatorio por norma.
 * ------------------------------------------------------------------- */
int tr31_selftest(void)
{
    uint8_t     kbek[TR31_SUBCHAVE_LEN], kbak[TR31_SUBCHAVE_LEN];
    uint8_t     chave[TR31_CHAVE_MAX];
    uint8_t     chave_n;
    tr31_cab_t  cab;
    char        bloco[TR31_ASCII_MAX];
    uint32_t    bloco_n, i;
    int         r = -1;

    if (tr31_deriva(kat_tr31_kbpk, kbek, kbak) != 0) {
        goto fim;
    }

    /* 1. o vetor */
    for (i = 0u; i < KAT_TR31_KB_LEN; i++) {
        bloco[i] = (char)kat_tr31_kb[i];
    }
    if (tr31_desembrulha(kbek, kbak, bloco, KAT_TR31_KB_LEN,
                         &cab, chave, &chave_n) != 0) {
        goto fim;
    }
    if (chave_n != KAT_TR31_KEY_LEN) {
        goto fim;
    }
    for (i = 0u; i < chave_n; i++) {
        if (chave[i] != kat_tr31_key[i]) {
            goto fim;
        }
    }

    /* 2. um bit trocado no cabecalho.
     *
     * O byte 11 e a EXPORTABILIDADE, e nao e escolha estetica: e o campo
     * que um atacante mais quer editar, e o que o MAC existe para
     * proteger. Depois de mexer, desembrulhar TEM de falhar. */
    bloco[11] = (bloco[11] == 'N') ? 'E' : 'N';
    if (tr31_desembrulha(kbek, kbak, bloco, KAT_TR31_KB_LEN,
                         &cab, chave, &chave_n) == 0) {
        goto fim;   /* aceitou cabecalho adulterado */
    }

    /* 3. ida e volta.
     *
     * Enchimento fixo, e nao do DRBG: o POST tem de dar o mesmo resultado
     * a cada boot, e um teste que depende do gerador testaria duas coisas
     * e diria qual falhou de nenhuma. O aleatorio de verdade entra no
     * comando de exportar. */
    cab.uso[0]          = (uint8_t)'D';
    cab.uso[1]          = (uint8_t)'0';
    cab.algoritmo       = (uint8_t)KS_ALG_AES;
    cab.modo            = (uint8_t)KS_MODO_AMBOS;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = (uint8_t)KS_EXP_SIM;

    for (i = 0u; i < TR31_CHAVE_MAX; i++) {
        chave[i] = (uint8_t)(0xA5u ^ i);
    }
    if (tr31_embrulha(kbek, kbak, &cab, chave, TR31_CHAVE_MAX,
                      kat_tr31_key, (uint8_t)KAT_TR31_KEY_LEN,
                      bloco, &bloco_n) != 0) {
        goto fim;
    }
    wipe(chave, sizeof chave);
    if (tr31_desembrulha(kbek, kbak, bloco, bloco_n,
                         &cab, chave, &chave_n) != 0) {
        goto fim;
    }
    if (chave_n != TR31_CHAVE_MAX) {
        goto fim;
    }
    for (i = 0u; i < chave_n; i++) {
        if (chave[i] != (uint8_t)(0xA5u ^ i)) {
            goto fim;
        }
    }
    r = 0;

fim:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(chave, sizeof chave);
    wipe(bloco, sizeof bloco);
    return r;
}
