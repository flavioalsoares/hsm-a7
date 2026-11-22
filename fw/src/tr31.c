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
#include "aes_modos.h"
#include "cmac.h"
#include "cmac_tdes.h"
#include "des.h"
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

/* Valida o cabecalho junto com o tamanho da chave: os dois juntos e que
 * dizem se o bloco faz sentido. Tem de casar com `_valida_campos()` de
 * host/tr31.py -- se um aceitar e o outro nao, um key block legitimo e
 * recusado de um lado e aceito do outro. */
static int cab_valido(const tr31_cab_t *cab, uint32_t chave_n)
{
    if (cab->exportabilidade != (uint8_t)KS_EXP_SIM &&
        cab->exportabilidade != (uint8_t)KS_EXP_NAO &&
        cab->exportabilidade != (uint8_t)KS_EXP_SENSIVEL) {
        return 0;
    }
    if (cab->algoritmo == (uint8_t)KS_ALG_RSA) {
        /* Fase 7: chave RSA de assinatura, e so. Outro uso ou modo seria
         * uma chave de assinar autorizada a fazer outra coisa. */
        return (cab->uso[0] == (uint8_t)'S') && (cab->uso[1] == (uint8_t)'0') &&
               (cab->modo == (uint8_t)KS_MODO_ASSINA) &&
               (chave_n > 0u) && (chave_n <= TR31_RSA_DER_MAX);
    }
    if (cab->algoritmo == (uint8_t)KS_ALG_EC) {
        /* Chave de ECDSA P-256: tambem so de assinatura. */
        return (cab->uso[0] == (uint8_t)'S') && (cab->uso[1] == (uint8_t)'0') &&
               (cab->modo == (uint8_t)KS_MODO_ASSINA) &&
               (chave_n > 0u) && (chave_n <= TR31_EC_DER_MAX);
    }
    if (cab->algoritmo == (uint8_t)KS_ALG_TDES) {
        /* Fase 8: chave 3DES de comprimento duplo ou triplo. DES simples
         * (8 bytes) nao existe aqui. */
        if (chave_n != 16u && chave_n != 24u) {
            return 0;
        }
    } else if (cab->algoritmo == (uint8_t)KS_ALG_AES) {
        if (chave_n == 0u || chave_n > TR31_CHAVE_MAX) {
            return 0;
        }
    } else {
        return 0;
    }
    /* Os sete modos de uso da X9.143 para chave simetrica, em dois grupos:
     * cifra (E/D/B) e MAC (G/V/C), mais 'N'. Tem de casar com
     * `header_valido()` do keystore -- se um aceitar e o outro nao, um key
     * block legitimo atravessa a importacao e para na instalacao, com o
     * erro apontando para o lugar errado. */
    if (cab->modo != (uint8_t)KS_MODO_CIFRA &&
        cab->modo != (uint8_t)KS_MODO_DECIFRA &&
        cab->modo != (uint8_t)KS_MODO_AMBOS &&
        cab->modo != (uint8_t)KS_MODO_NENHUM &&
        cab->modo != (uint8_t)KS_MODO_GERA &&
        cab->modo != (uint8_t)KS_MODO_VERIFICA &&
        cab->modo != (uint8_t)KS_MODO_MAC) {
        return 0;
    }
    return 1;
}

static void cab_escreve(char *dst, const tr31_cab_t *cab, uint32_t total,
                        char versao)
{
    dst[0]  = versao;
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
static uint32_t cab_le(const char *src, tr31_cab_t *cab, char versao)
{
    uint32_t total = 0u;
    uint32_t i;

    /* A versao vem de quem chama, e nao do bloco: sob a LMK so vale a D, sob
     * uma KEK 3DES so a B. Aceitar a que o bloco declarar deixaria o host
     * escolher a primitiva. */
    if (src[0] != versao) {
        return 0u;
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

/* Cabecalho + corpo em claro, contiguos: e exatamente o que o CMAC
 * autentica, e o corpo e cifrado e decifrado no lugar. Estatico porque a
 * chave RSA nao cabe na pilha com folga; apagado no fim de toda chamada.
 *
 * FRONTEIRA: dentro. Contem chave em claro enquanto uma funcao roda. */
static uint8_t g_kb[TR31_CAB_LEN + TR31_CORPO_GRANDE];
#define CORPO (&g_kb[TR31_CAB_LEN])

/* ---------------------------------------------------------------------
 * Embrulhar
 * ------------------------------------------------------------------- */
int tr31_embrulha_n(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                    const uint8_t kbak[TR31_SUBCHAVE_LEN],
                    const tr31_cab_t *cab,
                    const uint8_t *chave, uint16_t chave_n,
                    const uint8_t *enchimento, uint8_t enchimento_n,
                    char *saida, uint32_t *saida_n)
{
    uint8_t  mac[TR31_MAC_LEN];
    uint32_t corpo_n, falta, total, i;
    uint32_t bits;
    int      r = -1;

    if (!cab_valido(cab, chave_n) || chave_n > TR31_CHAVE_GRANDE) {
        return -1;
    }

    bits    = (uint32_t)chave_n * 8u;
    corpo_n = 2u + (uint32_t)chave_n;
    falta   = ((BLK - (corpo_n % BLK)) % BLK);

    if (enchimento_n < falta) {
        return -1;
    }

    CORPO[0] = (uint8_t)(bits >> 8);
    CORPO[1] = (uint8_t)(bits & 0xFFu);
    for (i = 0u; i < chave_n; i++) {
        CORPO[2u + i] = chave[i];
    }
    for (i = 0u; i < falta; i++) {
        CORPO[corpo_n + i] = enchimento[i];
    }
    corpo_n += falta;

    total = TR31_CAB_LEN + 2u * corpo_n + 2u * TR31_MAC_LEN;
    cab_escreve(saida, cab, total, 'D');

    /* O MAC cobre cabecalho + corpo EM CLARO, e so depois vira IV.
     * Autenticar o criptograma daria um MAC que nao diz nada sobre a
     * chave que esta la dentro. */
    for (i = 0u; i < TR31_CAB_LEN; i++) {
        g_kb[i] = (uint8_t)saida[i];
    }

    if (cmac_aes256(kbak, g_kb, TR31_CAB_LEN + corpo_n, mac) != 0) {
        goto fim;
    }
    /* A chave vai para o coprocessador aqui, e nao dentro do aes_cbc():
     * a funcao de modo nao ve chave nenhuma. */
    if (hsm_cfs_aes_key(kbek) != 0) {
        goto fim;
    }
    if (aes_cbc(mac, CORPO, CORPO, corpo_n, 1) != 0) {
        goto fim;
    }

    hex_escreve(&saida[TR31_CAB_LEN], CORPO, corpo_n);
    hex_escreve(&saida[TR31_CAB_LEN + 2u * corpo_n], mac, TR31_MAC_LEN);
    *saida_n = total;
    r = 0;

fim:
    wipe(g_kb, sizeof g_kb);
    wipe(mac, sizeof mac);
    return r;
}

int tr31_embrulha(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                  const uint8_t kbak[TR31_SUBCHAVE_LEN],
                  const tr31_cab_t *cab,
                  const uint8_t *chave, uint8_t chave_n,
                  const uint8_t *enchimento, uint8_t enchimento_n,
                  char *saida, uint32_t *saida_n)
{
    if (chave_n > TR31_CHAVE_MAX) {
        return -1;
    }
    return tr31_embrulha_n(kbek, kbak, cab, chave, chave_n,
                           enchimento, enchimento_n, saida, saida_n);
}

/* ---------------------------------------------------------------------
 * Desembrulhar
 *
 * A ordem e a parte que importa: autentica ANTES de acreditar em
 * qualquer campo do texto decifrado, e devolve o MESMO erro em todos os
 * caminhos de recusa.
 * ------------------------------------------------------------------- */
int tr31_desembrulha_n(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                       const uint8_t kbak[TR31_SUBCHAVE_LEN],
                       const char *bloco, uint32_t bloco_n,
                       tr31_cab_t *cab,
                       uint8_t *chave, uint16_t chave_max, uint16_t *chave_n)
{
    uint8_t  mac[TR31_MAC_LEN];
    uint32_t declarado, corpo_n, i;
    uint32_t bits;
    int      r = -1;

    *chave_n = 0u;

    if (bloco_n < TR31_CAB_LEN + 2u * BLK + 2u * TR31_MAC_LEN ||
        bloco_n > TR31_ASCII_GRANDE) {
        goto fim;
    }

    declarado = cab_le(bloco, cab, 'D');
    if (declarado != bloco_n) {
        /* O campo de comprimento entra no MAC, entao mentir nele ja
         * invalidaria o bloco -- conferir aqui e sobre nao decifrar o que
         * nem tem forma de bloco. */
        goto fim;
    }

    corpo_n = (bloco_n - TR31_CAB_LEN - 2u * TR31_MAC_LEN) / 2u;
    if (corpo_n == 0u || (corpo_n % BLK) != 0u || corpo_n > TR31_CORPO_GRANDE) {
        goto fim;
    }

    if (hex_le(&bloco[TR31_CAB_LEN], CORPO, corpo_n) != 0) {
        goto fim;
    }
    if (hex_le(&bloco[bloco_n - 2u * TR31_MAC_LEN], mac, TR31_MAC_LEN) != 0) {
        goto fim;
    }

    /* corpo entra cifrado e sai em claro, no mesmo buffer. */
    if (hsm_cfs_aes_key(kbek) != 0) {
        goto fim;
    }
    if (aes_cbc(mac, CORPO, CORPO, corpo_n, 0) != 0) {
        goto fim;
    }

    for (i = 0u; i < TR31_CAB_LEN; i++) {
        g_kb[i] = (uint8_t)bloco[i];
    }

    /* Verificacao em tempo constante -- ver cmac.h. */
    if (cmac_aes256_verifica(kbak, g_kb, TR31_CAB_LEN + corpo_n, mac) != 1) {
        goto fim;
    }

    /* So agora o conteudo decifrado merece credito. */
    bits = ((uint32_t)CORPO[0] << 8) | (uint32_t)CORPO[1];
    if ((bits % 8u) != 0u || bits == 0u) {
        goto fim;
    }
    if ((2u + bits / 8u) > corpo_n || (bits / 8u) > chave_max) {
        goto fim;
    }
    if (!cab_valido(cab, bits / 8u)) {
        goto fim;
    }

    *chave_n = (uint16_t)(bits / 8u);
    for (i = 0u; i < *chave_n; i++) {
        chave[i] = CORPO[2u + i];
    }
    r = 0;

fim:
    wipe(g_kb, sizeof g_kb);
    wipe(mac, sizeof mac);
    if (r != 0) {
        wipe(chave, chave_max);
        wipe(cab, sizeof *cab);
        *chave_n = 0u;
    }
    return r;
}

int tr31_desembrulha(const uint8_t kbek[TR31_SUBCHAVE_LEN],
                     const uint8_t kbak[TR31_SUBCHAVE_LEN],
                     const char *bloco, uint32_t bloco_n,
                     tr31_cab_t *cab,
                     uint8_t chave[TR31_CHAVE_MAX], uint8_t *chave_n)
{
    uint16_t n = 0u;
    int      r;

    r = tr31_desembrulha_n(kbek, kbak, bloco, bloco_n, cab,
                           chave, TR31_CHAVE_MAX, &n);
    *chave_n = (uint8_t)n;
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

/* =====================================================================
 * VERSAO B -- KBPK 3DES (fase 8, etapa 8.7). Ver tr31.h.
 *
 * Funcoes proprias, e nao a D com parametros: a D e validada e esta no POST
 * de todo boot. As duas tem a mesma ordem de passos, e devem ser lidas lado
 * a lado.
 * ===================================================================== */
#define BLK_B   TR31B_BLOCO
#define DERIV_B_DUPLA   0x0000u
#define DERIV_B_TRIPLA  0x0001u

static int deriva_b_uma(const uint8_t *kbpk, uint32_t n, uint16_t proposito,
                        uint8_t *saida)
{
    uint8_t  dados[8];
    uint16_t alg  = (n == TDES_CHAVE_3) ? DERIV_B_TRIPLA : DERIV_B_DUPLA;
    uint16_t bits = (uint16_t)(n * 8u);
    uint32_t contador;
    int      r = 0;

    for (contador = 1u; contador <= n / CMAC_TDES_TAG; contador++) {
        dados[0] = (uint8_t)contador;
        dados[1] = (uint8_t)(proposito >> 8);
        dados[2] = (uint8_t)(proposito & 0xFFu);
        dados[3] = 0x00u;
        dados[4] = (uint8_t)(alg >> 8);
        dados[5] = (uint8_t)(alg & 0xFFu);
        dados[6] = (uint8_t)(bits >> 8);
        dados[7] = (uint8_t)(bits & 0xFFu);
        if (cmac_tdes(kbpk, n, dados, sizeof dados,
                      &saida[(contador - 1u) * CMAC_TDES_TAG]) != 0) {
            r = -1;
            break;
        }
    }
    wipe(dados, sizeof dados);
    return r;
}

int tr31b_deriva(const uint8_t *kbpk, uint32_t n,
                 uint8_t kbek[TR31B_SUBCHAVE_MAX],
                 uint8_t kbak[TR31B_SUBCHAVE_MAX])
{
    if ((kbpk == 0) || (kbek == 0) || (kbak == 0) ||
        ((n != TDES_CHAVE_2) && (n != TDES_CHAVE_3)) ||
        (deriva_b_uma(kbpk, n, DERIV_KBEK, kbek) != 0) ||
        (deriva_b_uma(kbpk, n, DERIV_KBAK, kbak) != 0)) {
        if (kbek != 0) { wipe(kbek, TR31B_SUBCHAVE_MAX); }
        if (kbak != 0) { wipe(kbak, TR31B_SUBCHAVE_MAX); }
        return -1;
    }
    return 0;
}

int tr31b_embrulha(const uint8_t *kbek, const uint8_t *kbak, uint32_t n,
                   const tr31_cab_t *cab,
                   const uint8_t *chave, uint8_t chave_n,
                   const uint8_t *enchimento, uint8_t enchimento_n,
                   char *saida, uint32_t *saida_n)
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t     mac[TR31B_MAC_LEN];
    uint32_t    corpo_n, falta, total, i;
    uint32_t    bits;
    int         r = -1;

    if (((n != TDES_CHAVE_2) && (n != TDES_CHAVE_3)) ||
        !cab_valido(cab, chave_n) || (chave_n > TR31_CHAVE_MAX)) {
        return -1;
    }
    bits    = (uint32_t)chave_n * 8u;
    corpo_n = 2u + (uint32_t)chave_n;
    falta   = ((BLK_B - (corpo_n % BLK_B)) % BLK_B);
    if ((enchimento_n < falta) || (corpo_n + falta > TR31B_CORPO_MAX)) {
        return -1;
    }

    CORPO[0] = (uint8_t)(bits >> 8);
    CORPO[1] = (uint8_t)(bits & 0xFFu);
    for (i = 0u; i < chave_n; i++) {
        CORPO[2u + i] = chave[i];
    }
    for (i = 0u; i < falta; i++) {
        CORPO[corpo_n + i] = enchimento[i];
    }
    corpo_n += falta;

    total = TR31_CAB_LEN + 2u * corpo_n + 2u * TR31B_MAC_LEN;
    cab_escreve(saida, cab, total, 'B');
    for (i = 0u; i < TR31_CAB_LEN; i++) {
        g_kb[i] = (uint8_t)saida[i];
    }

    /* MAC sobre cabecalho + corpo em claro; depois ele e o IV. */
    if (cmac_tdes(kbak, n, g_kb, TR31_CAB_LEN + corpo_n, mac) != 0) {
        goto fim;
    }
    if ((tdes_prepara(ctx, kbek, n) != 0) ||
        (tdes_cbc(ctx, mac, CORPO, CORPO, corpo_n, 1) != 0)) {
        goto fim;
    }
    hex_escreve(&saida[TR31_CAB_LEN], CORPO, corpo_n);
    hex_escreve(&saida[TR31_CAB_LEN + 2u * corpo_n], mac, TR31B_MAC_LEN);
    *saida_n = total;
    r = 0;

fim:
    tdes_apaga(ctx);
    wipe(g_kb, sizeof g_kb);
    wipe(mac, sizeof mac);
    return r;
}

int tr31b_desembrulha(const uint8_t *kbek, const uint8_t *kbak, uint32_t n,
                      const char *bloco, uint32_t bloco_n,
                      tr31_cab_t *cab,
                      uint8_t chave[TR31_CHAVE_MAX], uint8_t *chave_n)
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t     mac[TR31B_MAC_LEN];
    uint32_t    declarado, corpo_n, i;
    uint32_t    bits;
    int         r = -1;

    *chave_n = 0u;

    if (((n != TDES_CHAVE_2) && (n != TDES_CHAVE_3)) ||
        (bloco_n < TR31_CAB_LEN + 2u * BLK_B + 2u * TR31B_MAC_LEN) ||
        (bloco_n > TR31B_ASCII_MAX)) {
        goto fim;
    }
    declarado = cab_le(bloco, cab, 'B');
    if (declarado != bloco_n) {
        goto fim;
    }
    corpo_n = (bloco_n - TR31_CAB_LEN - 2u * TR31B_MAC_LEN) / 2u;
    if ((corpo_n == 0u) || ((corpo_n % BLK_B) != 0u) ||
        (corpo_n > TR31B_CORPO_MAX) ||
        ((bloco_n - TR31_CAB_LEN) % 2u != 0u)) {
        goto fim;
    }
    if ((hex_le(&bloco[TR31_CAB_LEN], CORPO, corpo_n) != 0) ||
        (hex_le(&bloco[bloco_n - 2u * TR31B_MAC_LEN], mac,
                TR31B_MAC_LEN) != 0)) {
        goto fim;
    }
    if ((tdes_prepara(ctx, kbek, n) != 0) ||
        (tdes_cbc(ctx, mac, CORPO, CORPO, corpo_n, 0) != 0)) {
        goto fim;
    }
    tdes_apaga(ctx);   /* o CMAC abaixo usa o mesmo contexto */
    for (i = 0u; i < TR31_CAB_LEN; i++) {
        g_kb[i] = (uint8_t)bloco[i];
    }
    if (cmac_tdes_verifica(kbak, n, g_kb, TR31_CAB_LEN + corpo_n, mac) != 1) {
        goto fim;
    }

    /* So agora o conteudo decifrado merece credito. */
    bits = ((uint32_t)CORPO[0] << 8) | (uint32_t)CORPO[1];
    if (((bits % 8u) != 0u) || (bits == 0u) ||
        ((2u + bits / 8u) > corpo_n) || ((bits / 8u) > TR31_CHAVE_MAX) ||
        !cab_valido(cab, bits / 8u)) {
        goto fim;
    }
    *chave_n = (uint8_t)(bits / 8u);
    for (i = 0u; i < *chave_n; i++) {
        chave[i] = CORPO[2u + i];
    }
    r = 0;

fim:
    tdes_apaga(ctx);
    wipe(g_kb, sizeof g_kb);
    wipe(mac, sizeof mac);
    if (r != 0) {
        wipe(chave, TR31_CHAVE_MAX);
        wipe(cab, sizeof *cab);
        *chave_n = 0u;
    }
    return r;
}

/* Autoteste da versao B, no primeiro uso do 3DES. As mesmas tres
 * verificacoes de tr31_selftest(), mais o CMAC-TDES sozinho, antes: se ele
 * falhar, o bloco falha por um motivo que o vetor do CMAC ja aponta. */
int tr31b_selftest(void)
{
    uint8_t    kbek[TR31B_SUBCHAVE_MAX], kbak[TR31B_SUBCHAVE_MAX];
    uint8_t    chave[TR31_CHAVE_MAX];
    uint8_t    chave_n = 0u;
    tr31_cab_t cab;
    char       bloco[TR31B_ASCII_MAX];
    uint32_t   bloco_n = 0u, i;
    int        r = -1;

    /* 0. o CMAC-TDES, tag cheia de 8 bytes */
    if (cmac_tdes_verifica(kat_cmac_tdes_chave, TDES_CHAVE_3,
                           kat_cmac_tdes_msg, KAT_CMAC_TDES_MSG_LEN,
                           kat_cmac_tdes_tag) != 1) {
        goto fim;
    }
    if (tr31b_deriva(kat_tr31b_kbpk, KAT_TR31B_KBPK_LEN, kbek, kbak) != 0) {
        goto fim;
    }
    /* 1. o bloco de terceiros */
    for (i = 0u; i < KAT_TR31B_KB_LEN; i++) {
        bloco[i] = (char)kat_tr31b_kb[i];
    }
    if ((tr31b_desembrulha(kbek, kbak, KAT_TR31B_KBPK_LEN, bloco,
                           KAT_TR31B_KB_LEN, &cab, chave, &chave_n) != 0) ||
        (chave_n != KAT_TR31B_KEY_LEN)) {
        goto fim;
    }
    for (i = 0u; i < chave_n; i++) {
        if (chave[i] != kat_tr31b_key[i]) {
            goto fim;
        }
    }
    /* 2. a exportabilidade trocada tem de ser recusada */
    bloco[11] = (bloco[11] == 'N') ? 'E' : 'N';
    if (tr31b_desembrulha(kbek, kbak, KAT_TR31B_KBPK_LEN, bloco,
                          KAT_TR31B_KB_LEN, &cab, chave, &chave_n) == 0) {
        goto fim;
    }
    /* 3. ida e volta, com enchimento fixo */
    cab.uso[0]          = (uint8_t)'K';
    cab.uso[1]          = (uint8_t)'0';
    cab.algoritmo       = (uint8_t)KS_ALG_TDES;
    cab.modo            = (uint8_t)KS_MODO_AMBOS;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = (uint8_t)KS_EXP_SIM;
    for (i = 0u; i < TDES_CHAVE_3; i++) {
        chave[i] = (uint8_t)(0x5Au ^ i);
    }
    if (tr31b_embrulha(kbek, kbak, KAT_TR31B_KBPK_LEN, &cab, chave,
                       TDES_CHAVE_3, kat_tr31b_key, KAT_TR31B_KEY_LEN,
                       bloco, &bloco_n) != 0) {
        goto fim;
    }
    wipe(chave, sizeof chave);
    if ((tr31b_desembrulha(kbek, kbak, KAT_TR31B_KBPK_LEN, bloco, bloco_n,
                           &cab, chave, &chave_n) != 0) ||
        (chave_n != TDES_CHAVE_3)) {
        goto fim;
    }
    for (i = 0u; i < chave_n; i++) {
        if (chave[i] != (uint8_t)(0x5Au ^ i)) {
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
