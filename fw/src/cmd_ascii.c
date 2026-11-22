/* fw/src/cmd_ascii.c -- porta HOST: command set ASCII (fase 5)
 *
 * FRONTEIRA: fora -- este modulo ve a mensagem do host. A chave de
 * trabalho chega embrulhada num key block sob a LMK; e aberta aqui e
 * instalada no slot EFEMERO do key store, de onde e usada pelas mesmas
 * funcoes do console. O despachante apaga o slot efemero depois de TODO
 * comando, em qualquer desfecho. Formato e codigos: doc/fase5-notas.md.
 *
 * O que separa esta porta do console nao e a sintaxe. E o modelo: aqui o
 * dispositivo nao guarda a chave de trabalho de ninguem. O host a mantem
 * no banco de dados dele, como key block, e a manda a cada comando. Nada
 * de cerimonia passa por aqui -- nenhum comando desta tabela carrega
 * componente, muda estado ou zeroiza.
 *
 * Mesma disciplina do parser binario: leitura por cursor com limite
 * checado a cada campo, sem alocacao, e a mensagem inteira e validada ANTES
 * de o key block ser aberto -- um pedido malformado nao chega a carregar
 * chave nenhuma.
 */
#include "cmd_ascii.h"
#include "rsa.h"
#include "ecc.h"
#include "kat.h"
#include "versao.h"
#include "aes_modos.h"
#include "audit_log.h"
#include "cmac.h"
#include "drbg.h"
#include "hsm_cfs.h"
#include "keystore.h"
#include "state.h"
#include "pinblock.h"
#include "pinverif.h"
#include "cvv.h"
#include "des.h"
#include "kat.h"
#include "tr31.h"
#include "wipe.h"

/* ------------------------------------------------------------------ */
/* Leitura e escrita por cursor                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *p;
    uint16_t       n;
    uint16_t       pos;
} leitor_t;

typedef struct {
    uint8_t  *p;
    uint16_t  max;
    uint16_t  n;
    uint8_t   estouro;    /* 1 se alguem tentou escrever alem do fim */
} escritor_t;

static void poe(escritor_t *w, uint8_t c)
{
    if (w->n >= w->max) {
        w->estouro = 1u;
        return;
    }
    w->p[w->n++] = c;
}

static void poe_hex(escritor_t *w, const uint8_t *b, uint32_t n)
{
    static const char dig[] = "0123456789ABCDEF";
    uint32_t i;

    for (i = 0u; i < n; i++) {
        poe(w, (uint8_t)dig[b[i] >> 4]);
        poe(w, (uint8_t)dig[b[i] & 0x0Fu]);
    }
}

static void poe_dec(escritor_t *w, uint32_t v, uint8_t digitos)
{
    uint32_t div = 1u;
    uint8_t  i;

    for (i = 1u; i < digitos; i++) {
        div *= 10u;
    }
    for (i = 0u; i < digitos; i++) {
        poe(w, (uint8_t)('0' + (v / div) % 10u));
        div /= 10u;
    }
}

static int hexval(uint8_t c)
{
    if ((c >= '0') && (c <= '9')) { return (int)(c - '0'); }
    if ((c >= 'A') && (c <= 'F')) { return (int)(c - 'A' + 10); }
    if ((c >= 'a') && (c <= 'f')) { return (int)(c - 'a' + 10); }
    return -1;
}

/* `n` digitos decimais. -1 se faltam caracteres, -2 se nao sao digitos. */
static int32_t le_dec(leitor_t *r, uint8_t n)
{
    int32_t v = 0;
    uint8_t i, c;

    if ((uint32_t)r->pos + n > r->n) {
        return -1;
    }
    for (i = 0u; i < n; i++) {
        c = r->p[r->pos + i];
        if ((c < '0') || (c > '9')) {
            return -2;
        }
        v = v * 10 + (int32_t)(c - '0');
    }
    r->pos = (uint16_t)(r->pos + n);
    return v;
}

/* `n` bytes em hex. Devolve um codigo de erro ASCII. */
static uint8_t le_hex(leitor_t *r, uint8_t *out, uint32_t n)
{
    uint32_t i;
    int      hi, lo;

    if ((uint32_t)r->pos + 2u * n > r->n) {
        return ASCII_MALFORMADA;
    }
    for (i = 0u; i < n; i++) {
        hi = hexval(r->p[r->pos + 2u * i]);
        lo = hexval(r->p[r->pos + 2u * i + 1u]);
        if ((hi < 0) || (lo < 0)) {
            return ASCII_DADOS;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    r->pos = (uint16_t)(r->pos + 2u * n);
    return ASCII_OK;
}

/* Campo de dados: comprimento em 4 digitos decimais + hex. */
static uint8_t le_dados(leitor_t *r, uint8_t *out, uint32_t max,
                        uint32_t *n)
{
    int32_t v = le_dec(r, 4u);

    if (v == -1) {
        return ASCII_MALFORMADA;
    }
    if ((v < 0) || ((uint32_t)v > max)) {
        return ASCII_DADOS;
    }
    *n = (uint32_t)v;
    return le_hex(r, out, (uint32_t)v);
}

/* Key block: o comprimento sai do PROPRIO cabecalho do bloco (posicoes
 * 1..4), entao o campo se delimita sozinho. Aqui so se acha onde ele
 * termina; quem decide se ele e valido e o tr31_desembrulha(). */
static uint8_t le_bloco(leitor_t *r, const uint8_t **b, uint16_t *bn)
{
    leitor_t t;
    int32_t  v;

    if ((uint32_t)r->pos + TR31_CAB_LEN > r->n) {
        return ASCII_MALFORMADA;
    }
    t.p   = r->p;
    t.n   = r->n;
    t.pos = (uint16_t)(r->pos + 1u);
    v = le_dec(&t, 4u);
    if ((v < (int32_t)TR31_CAB_LEN) || (v > (int32_t)TR31_ASCII_GRANDE)) {
        return ASCII_BLOCO_INVAL;
    }
    if ((uint32_t)r->pos + (uint32_t)v > r->n) {
        return ASCII_MALFORMADA;
    }
    *b     = &r->p[r->pos];
    *bn    = (uint16_t)v;
    r->pos = (uint16_t)(r->pos + (uint16_t)v);
    return ASCII_OK;
}

static uint8_t fim(const leitor_t *r)
{
    return (r->pos == r->n) ? ASCII_OK : ASCII_MALFORMADA;
}

/* ------------------------------------------------------------------ */
/* O key block do comando                                              */
/* ------------------------------------------------------------------ */

/* Abre um bloco sob KBEK/KBAK dadas e instala a chave no slot efemero.
 *
 * FRONTEIRA: dentro. `chave` existe na pilha so durante esta funcao e sai
 * zerada. Malformado, MAC errado, feito sob outra chave de protecao ou
 * com cabecalho que o key store recusa: tudo e ASCII_BLOCO_INVAL --
 * distinguir seria o oraculo de padding (ver IMPORT_KEY em cmd.c). */
static uint8_t primeiro_uso(unsigned qual);

static uint8_t abre_sob(const uint8_t kbek[KS_KEY_MAX],
                        const uint8_t kbak[KS_KEY_MAX],
                        const uint8_t *b, uint16_t bn, ks_info_t *info)
{
    uint8_t    chave[TR31_CHAVE_MAX];
    uint8_t    klen = 0u;
    tr31_cab_t cab;
    uint8_t    r = ASCII_INTERNO;

    if (tr31_desembrulha(kbek, kbak, (const char *)b, bn,
                         &cab, chave, &klen) != 0) {
        r = ASCII_BLOCO_INVAL;
        goto sai;
    }
    /* Chave 3DES: o autoteste de primeiro uso roda antes de a chave ser
     * usada, e ja a instalacao a usa, para o KCV. */
    if ((cab.algoritmo == (uint8_t)KS_ALG_TDES) &&
        (primeiro_uso(KAT_FALHA_TDES) != ASCII_OK)) {
        r = ASCII_ERRO_GRAVE;
        goto sai;
    }
    if (keystore_efemera(cab.uso, cab.algoritmo, cab.modo,
                         cab.exportabilidade, chave, klen)
        != KS_HANDLE_EFEMERA) {
        r = ASCII_BLOCO_INVAL;
        goto sai;
    }
    r = (keystore_info(KS_HANDLE_EFEMERA, info) == 0) ? ASCII_OK
                                                      : ASCII_INTERNO;
sai:
    wipe(chave, sizeof chave);
    return r;
}

/* O caso comum: o bloco que o host guarda, sob a LMK. */
static uint8_t abre_bloco(const uint8_t *b, uint16_t bn, ks_info_t *info)
{
    uint8_t kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t r = ASCII_INTERNO;

    if (lmk_deriva_kb(kbek, kbak) == 0) {
        r = abre_sob(kbek, kbak, b, bn, info);
    }
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    return r;
}

/* Abre o bloco de uma KEK (sob a LMK) e devolve as subchaves dela para
 * embrulhar (KS_MODO_CIFRA) ou desembrulhar (KS_MODO_DECIFRA). A KEK sai
 * do slot efemero antes de a funcao voltar: o slot fica livre para a
 * chave que ela protege, e a KEK em si nunca esta ao lado dela.
 *
 * FRONTEIRA: dentro. O chamador zeroiza `kbek` e `kbak`. */
static uint8_t kek_subchaves(const uint8_t *b, uint16_t bn, uint8_t modo,
                             uint8_t kbek[KS_KEY_MAX],
                             uint8_t kbak[KS_KEY_MAX])
{
    ks_info_t info;
    uint8_t   r;
    int       v;

    if ((r = abre_bloco(b, bn, &info)) != ASCII_OK) {
        return r;
    }
    v = keystore_kek_deriva(KS_HANDLE_EFEMERA, modo, kbek, kbak);
    keystore_efemera_apaga();
    if (v == -2) { return ASCII_NAO_KEK; }
    if (v == -3) { return ASCII_MODO; }
    return (v == 0) ? ASCII_OK : ASCII_INTERNO;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

/* Dados de entrada e de saida dos comandos de cifra e MAC. Estaticos pelo
 * mesmo motivo de g_out em cmd.c, e zerados pelo despachante. */
static uint8_t g_dados[ASCII_DADOS_MAX];
static uint8_t g_res[ASCII_DADOS_MAX];

typedef uint8_t (*ascii_handler_t)(leitor_t *in, escritor_t *out);

/* D0 -- diagnostico: estado(1) . KCV da LMK(6) . versao(6).
 *
 * Checklist: todo estado normal; sem dual control; nao vaza nada que o
 * console nao entregue (GET_VERSION, LMK_STATUS); nao ha chave; nao entra
 * no log, como os informativos do console. O host confere o KCV da LMK
 * antes de confiar que os blocos dele foram feitos sob ela. */
static uint8_t h_d0(leitor_t *in, escritor_t *out)
{
    uint8_t kcv[KS_KCV_LEN];

    if (fim(in) != ASCII_OK) {
        return ASCII_MALFORMADA;
    }
    if (lmk_kcv(kcv) != 0) {
        kcv[0] = kcv[1] = kcv[2] = 0u;
    }
    poe(out, (uint8_t)('0' + (uint8_t)state_get()));
    poe_hex(out, kcv, KS_KCV_LEN);
    poe_dec(out, HSM_VERSAO_MAJOR, 2u);
    poe_dec(out, HSM_VERSAO_MINOR, 2u);
    poe_dec(out, HSM_VERSAO_PATCH, 2u);
    return ASCII_OK;
}

/* K0 -- gerar chave: uso(2) . modo(1) . exportabilidade(1)
 *       [. algoritmo(1) . comprimento(1)]
 *       -> key block sob a LMK . KCV(6)
 *
 * Os dois ultimos campos sao opcionais, e vem juntos. Sem eles, a chave e
 * AES-256. "A4" e AES-256; "T2" e 3DES de comprimento duplo (16 bytes);
 * "T3" e 3DES de comprimento triplo (24 bytes). O digito e o tamanho da
 * chave em blocos de 8 bytes. Outro valor: 16.
 *
 * A chave 3DES sai com paridade impar em todo byte, e a geracao sorteia de
 * novo se cair numa chave fraca ou com partes iguais (SP 800-67).
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao.
 *   vazamento    em laco, chaves novas e independentes, cada uma so
 *                embrulhada. Nenhuma fica no dispositivo.
 *   exportability nao se aplica a ESTE caminho: o bloco volta sob a LMK,
 *                e guardar a chave no banco do host sob a LMK nao e
 *                exportar -- ela so abre dentro deste dispositivo. Por isso
 *                'N' tambem volta como bloco.
 *   log          sim, antes.
 *
 * FRONTEIRA: dentro. A chave nasce no DRBG, passa pelo slot efemero (que
 * valida o cabecalho e calcula o KCV) e sai so embrulhada. */
static uint8_t h_k0(leitor_t *in, escritor_t *out)
{
    uint8_t    kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t    chave[KS_KEY_MAX];
    uint8_t    enchimento[TR31_BLOCO];
    char       bloco[TR31_ASCII_MAX];
    uint32_t   bn = 0u;
    tr31_cab_t cab;
    ks_info_t  info;
    uint8_t    uso[2], modo, exp;
    uint8_t    alg = KS_ALG_AES, klen = KS_KEY_MAX;
    uint8_t    r = ASCII_INTERNO;
    uint32_t   i, tenta;

    if (((uint32_t)in->pos + 4u) > in->n) {
        return ASCII_MALFORMADA;
    }
    uso[0] = in->p[in->pos];
    uso[1] = in->p[in->pos + 1u];
    modo   = in->p[in->pos + 2u];
    exp    = in->p[in->pos + 3u];
    in->pos = (uint16_t)(in->pos + 4u);
    if (in->pos != in->n) {
        uint8_t a, c;
        if (((uint32_t)in->pos + 2u) != in->n) {
            return ASCII_MALFORMADA;
        }
        a = in->p[in->pos];
        c = in->p[in->pos + 1u];
        in->pos = (uint16_t)(in->pos + 2u);
        if ((a == (uint8_t)KS_ALG_AES) && (c == (uint8_t)'4')) {
            alg = KS_ALG_AES;  klen = KS_KEY_MAX;
        } else if ((a == (uint8_t)KS_ALG_TDES) && (c == (uint8_t)'2')) {
            alg = KS_ALG_TDES; klen = TDES_CHAVE_2;
        } else if ((a == (uint8_t)KS_ALG_TDES) && (c == (uint8_t)'3')) {
            alg = KS_ALG_TDES; klen = TDES_CHAVE_3;
        } else {
            return ASCII_PARAM;
        }
    }

    if (alg == KS_ALG_TDES) {
        if (primeiro_uso(KAT_FALHA_TDES) != ASCII_OK) {
            return ASCII_ERRO_GRAVE;
        }
        /* Sorteia de novo se a chave for fraca. A chance e desprezivel; o
         * limite existe para o laco terminar se o DRBG falhar em silencio. */
        for (tenta = 0u; tenta < 8u; tenta++) {
            if (drbg_dispositivo_bytes(chave, klen) != 0) {
                goto sai;
            }
            des_paridade_ajusta(chave, klen);
            if (!tdes_chave_ruim(chave, klen)) {
                break;
            }
        }
        if (tenta == 8u) {
            goto sai;
        }
    } else if (drbg_dispositivo_bytes(chave, klen) != 0) {
        goto sai;
    }
    if (keystore_efemera(uso, alg, modo, exp, chave, klen)
        != KS_HANDLE_EFEMERA) {
        r = ASCII_PARAM;
        goto sai;
    }
    if (keystore_info(KS_HANDLE_EFEMERA, &info) != 0) {
        goto sai;
    }
    if (drbg_dispositivo_bytes(enchimento, sizeof enchimento) != 0) {
        goto sai;
    }
    if (lmk_deriva_kb(kbek, kbak) != 0) {
        goto sai;
    }
    cab.uso[0]          = uso[0];
    cab.uso[1]          = uso[1];
    cab.algoritmo       = alg;
    cab.modo            = modo;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = exp;
    if (tr31_embrulha(kbek, kbak, &cab, chave, klen,
                      enchimento, (uint8_t)sizeof enchimento,
                      bloco, &bn) != 0) {
        goto sai;
    }
    for (i = 0u; i < bn; i++) {
        poe(out, (uint8_t)bloco[i]);
    }
    poe_hex(out, info.kcv, KS_KCV_LEN);
    r = ASCII_OK;

sai:
    wipe(chave, sizeof chave);
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(enchimento, sizeof enchimento);
    wipe(bloco, sizeof bloco);
    return r;
}

/* K2 -- conferir key block: bloco -> uso(2) . alg(1) . modo(1) . exp(1)
 *       . KCV(6)
 *
 * Checklist: OPERATIONAL (precisa da LMK); sem dual control; vaza o que o
 * KEY_INFO do console vaza -- cabecalho, que ja e publico no bloco, e 3
 * bytes de KCV; nada de chave; informativo, fora do log. */
static uint8_t h_k2(leitor_t *in, escritor_t *out)
{
    const uint8_t *b = 0;
    uint16_t       bn = 0u;
    ks_info_t      info;
    uint8_t        r;

    if ((r = le_bloco(in, &b, &bn)) != ASCII_OK) { return r; }
    if ((r = fim(in)) != ASCII_OK)               { return r; }
    if ((r = abre_bloco(b, bn, &info)) != ASCII_OK) { return r; }

    poe(out, info.uso[0]);
    poe(out, info.uso[1]);
    poe(out, info.algoritmo);
    poe(out, info.modo);
    poe(out, info.exportabilidade);
    poe_hex(out, info.kcv, KS_KCV_LEN);
    return ASCII_OK;
}

/* C0 / C2 -- AES-256-CBC: bloco . IV(32) . dados -> dados
 *
 * Checklist: OPERATIONAL; sem dual control; e um oraculo de cifragem sob a
 * chave do bloco, como o ENCRYPT do console -- e o servico. O que limita e
 * o `modo` do bloco, autenticado pelo MAC dele: 'E' so cifra, 'D' so
 * decifra. Entra no log, antes. */
static uint8_t cripto(leitor_t *in, escritor_t *out, int cifrar)
{
    int            v;
    const uint8_t *b = 0;
    uint16_t       bn = 0u;
    uint8_t        iv[AES_BLOCO];
    uint32_t       n = 0u;
    ks_info_t      info;
    uint8_t        r;

    if ((r = le_bloco(in, &b, &bn)) != ASCII_OK)               { return r; }
    if ((r = le_hex(in, iv, AES_BLOCO)) != ASCII_OK)           { return r; }
    if ((r = le_dados(in, g_dados, ASCII_DADOS_MAX, &n)) != ASCII_OK) {
        return r;
    }
    if ((r = fim(in)) != ASCII_OK)                             { return r; }
    if ((n == 0u) || ((n % AES_BLOCO) != 0u)) {
        return ASCII_DADOS;
    }
    if ((r = abre_bloco(b, bn, &info)) != ASCII_OK)            { return r; }

    v = keystore_cbc_confere(KS_HANDLE_EFEMERA,
                             cifrar ? (uint8_t)KS_MODO_CIFRA
                                    : (uint8_t)KS_MODO_DECIFRA,
                             iv, g_dados, g_res, n, cifrar);
    if (v == -1) {
        return ASCII_MODO;
    }
    if (v != 0) {
        return (v == -2) ? ASCII_ERRO_GRAVE : ASCII_INTERNO;
    }
    poe_dec(out, n, 4u);
    poe_hex(out, g_res, n);
    return ASCII_OK;
}

static uint8_t h_c0(leitor_t *in, escritor_t *out) { return cripto(in, out, 1); }
static uint8_t h_c2(leitor_t *in, escritor_t *out) { return cripto(in, out, 0); }

/* M0 -- CMAC-AES-256: bloco . dados -> MAC(32)
 *
 * Checklist: OPERATIONAL; sem dual control; oraculo de MAC sob a chave do
 * bloco, que e o servico; 'G' ou 'C' no `modo`; entra no log. */
static uint8_t h_m0(leitor_t *in, escritor_t *out)
{
    int            v;
    const uint8_t *b = 0;
    uint16_t       bn = 0u;
    uint8_t        tag[CMAC_TAG_LEN];
    uint32_t       n = 0u;
    ks_info_t      info;
    uint8_t        r;

    if ((r = le_bloco(in, &b, &bn)) != ASCII_OK)               { return r; }
    if ((r = le_dados(in, g_dados, ASCII_DADOS_MAX, &n)) != ASCII_OK) {
        return r;
    }
    if ((r = fim(in)) != ASCII_OK)                             { return r; }
    if ((r = abre_bloco(b, bn, &info)) != ASCII_OK)            { return r; }

    v = keystore_cmac(KS_HANDLE_EFEMERA, (n > 0u) ? g_dados : 0, n, tag);
    if (v != 0) {
        return (v == -2) ? ASCII_ERRO_GRAVE : ASCII_MODO;
    }
    poe_hex(out, tag, CMAC_TAG_LEN);
    return ASCII_OK;
}

/* M2 -- verificar: bloco . MAC(32) . dados -> veredito no codigo de erro
 *
 * UM BIT: 00 confere, 01 nao confere. A comparacao e em tempo constante,
 * dentro do key store. Devolver o MAC calculado entregaria 128 bits.
 * 'V' ou 'C' no `modo`; entra no log. */
static uint8_t h_m2(leitor_t *in, escritor_t *out)
{
    const uint8_t *b = 0;
    uint16_t       bn = 0u;
    uint8_t        tag[CMAC_TAG_LEN];
    uint32_t       n = 0u;
    ks_info_t      info;
    uint8_t        r;
    int            v;

    (void)out;
    if ((r = le_bloco(in, &b, &bn)) != ASCII_OK)               { return r; }
    if ((r = le_hex(in, tag, CMAC_TAG_LEN)) != ASCII_OK)       { return r; }
    if ((r = le_dados(in, g_dados, ASCII_DADOS_MAX, &n)) != ASCII_OK) {
        return r;
    }
    if ((r = fim(in)) != ASCII_OK)                             { return r; }
    if ((r = abre_bloco(b, bn, &info)) != ASCII_OK)            { return r; }

    v = keystore_cmac_verifica(KS_HANDLE_EFEMERA, (n > 0u) ? g_dados : 0,
                               n, tag);
    if (v == -2) {
        return ASCII_ERRO_GRAVE;
    }
    if (v < 0) {
        return ASCII_MODO;
    }
    return (v == 1) ? ASCII_OK : ASCII_VERIF_FALHOU;
}

/* Autoteste de primeiro uso (kat.h), antes de um comando de assinatura
 * RSA ou de ECDSA. Reprovou: o mesmo destino de um POST reprovado -- a
 * BRAM e apagada e o dispositivo vai para TAMPERED. O comando responde 91.
 *
 * Roda ANTES de abrir qualquer key block: o autoteste termina apagando o
 * coprocessador. */
static uint8_t primeiro_uso(unsigned qual)
{
    if (kat_primeiro_uso(qual) == 0) {
        return ASCII_OK;
    }
    (void)keystore_zeroiza_tudo();
    state_set(HSM_TAMPERED);
    return ASCII_ERRO_GRAVE;
}

/* Numeros RSA de R2 e R4: estaticos para nao pesar na pilha. So dados
 * publicos -- modulo e assinatura. */
static uint8_t g_rsa_n[RSA_BYTES], g_rsa_s[RSA_BYTES];

/* R0 -- gerar par RSA: exportabilidade(1) -> key block da chave privada
 *       (sob a LMK) . n(512) . e(8). RSA-2048, e = 65537.
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao, como o K0.
 *   em laco      pares novos e independentes, cada um so embrulhado. Leva
 *                segundos: o laco gasta tempo, nao vaza.
 *   exportacao   como no K0: o bloco volta sob a LMK, e guarda-lo no host
 *                nao e exportar. 'N' tambem volta como bloco.
 *   log          sim, antes.
 *
 * O par passa por um teste de consistencia (assinar e verificar) antes de
 * sair. Erro 91 se ele falhar: o erro grave fica marcado.
 *
 * FRONTEIRA: dentro. p e q nascem no keystore e saem so embrulhados; o
 * bloco e escrito direto na resposta. */
static uint8_t h_r0(leitor_t *in, escritor_t *out)
{
    uint32_t bn = 0u;
    uint8_t  exp;
    uint8_t  ee[4];
    int      v;

    if (((uint32_t)in->pos + 1u) > in->n) {
        return ASCII_MALFORMADA;
    }
    exp = in->p[in->pos];
    in->pos = (uint16_t)(in->pos + 1u);
    if (fim(in) != ASCII_OK) {
        return ASCII_MALFORMADA;
    }
    if ((uint32_t)out->n + TR31_ASCII_GRANDE + 2u * RSA_BYTES + 8u > out->max) {
        return ASCII_INTERNO;
    }
    if (primeiro_uso(KAT_FALHA_RSA_ASSINA) != ASCII_OK) {
        return ASCII_ERRO_GRAVE;
    }
    v = keystore_rsa_gera(exp, (char *)&out->p[out->n],
                          (uint32_t)(out->max - out->n), &bn, g_rsa_n, g_rsa_s);
    if (v == -2) { return ASCII_ERRO_GRAVE; }
    if (v != 0)  { return (exp == 'E' || exp == 'N' || exp == 'S') ? ASCII_INTERNO
                                                                  : ASCII_PARAM; }
    out->n = (uint16_t)(out->n + bn);
    poe_hex(out, g_rsa_n, RSA_BYTES);
    ee[0] = (uint8_t)(RSA_E_PADRAO >> 24);
    ee[1] = (uint8_t)(RSA_E_PADRAO >> 16);
    ee[2] = (uint8_t)(RSA_E_PADRAO >> 8);
    ee[3] = (uint8_t)RSA_E_PADRAO;
    poe_hex(out, ee, 4u);
    wipe(g_rsa_s, sizeof g_rsa_s);
    return ASCII_OK;
}

/* R2 -- assinar com RSA: key block da chave privada (sob a LMK) .
 *       digest(64) -> S(512). PKCS#1 v1.5 com SHA-256.
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao.
 *   em laco      e um oraculo de assinatura -- quem tem o bloco assina o
 *                que quiser, que e o servico. A assinatura e por CRT em
 *                tempo constante, e verificada antes de sair: uma falha de
 *                calculo nao entrega a fatoracao de n (Bellcore).
 *   exportacao   nao se aplica: a chave nao sai, e o bloco ja e do host.
 *   log          sim, antes.
 *
 * Erros: 10 bloco invalido, 11 bloco de outro tipo de chave, 91 a
 * verificacao reprovou (nada sai, erro grave marcado).
 *
 * FRONTEIRA: dentro. A chave abre no keystore e fica la; o despachante a
 * apaga no fim do comando. */
static uint8_t h_r2(leitor_t *in, escritor_t *out)
{
    const uint8_t *b = 0;
    uint16_t       bn = 0u;
    uint8_t        digest[RSA_SHA256_LEN];
    uint8_t        r;
    int            v;

    if ((r = le_bloco(in, &b, &bn)) != ASCII_OK)               { return r; }
    if ((r = le_hex(in, digest, RSA_SHA256_LEN)) != ASCII_OK)  { return r; }
    if ((r = fim(in)) != ASCII_OK)                             { return r; }
    if ((r = primeiro_uso(KAT_FALHA_RSA_ASSINA)) != ASCII_OK)  { return r; }

    v = keystore_rsa_abre((const char *)b, bn);
    if (v == -3) { return ASCII_MODO; }
    if (v != 0)  { return ASCII_BLOCO_INVAL; }

    v = keystore_rsa_assina(digest, g_rsa_s);
    if (v == -2) { return ASCII_ERRO_GRAVE; }
    if (v != 0)  { return ASCII_INTERNO; }
    poe_hex(out, g_rsa_s, RSA_BYTES);
    wipe(g_rsa_s, sizeof g_rsa_s);
    return ASCII_OK;
}

/* R4 -- verificar assinatura RSA: n(512) . e(8) . digest(64) . S(512).
 *       Assinatura PKCS#1 v1.5 com SHA-256. Erro 01 se nao confere.
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao, e nao usa chave nenhuma do dispositivo.
 *   em laco      so dados publicos entram, e sai um bit.
 *   exportacao   nao se aplica.
 *   log          sim, antes de executar, como M2.
 */
static uint8_t h_r4(leitor_t *in, escritor_t *out)
{
    uint8_t       *n = g_rsa_n, *s = g_rsa_s;
    uint8_t        ee[4], digest[RSA_SHA256_LEN];
    uint32_t       e;
    uint8_t        r;
    int            v, v2;

    (void)out;
    if ((r = le_hex(in, n, RSA_BYTES)) != ASCII_OK)            { return r; }
    if ((r = le_hex(in, ee, 4u)) != ASCII_OK)                  { return r; }
    if ((r = le_hex(in, digest, RSA_SHA256_LEN)) != ASCII_OK)  { return r; }
    if ((r = le_hex(in, s, RSA_BYTES)) != ASCII_OK)            { return r; }
    if ((r = fim(in)) != ASCII_OK)                             { return r; }

    e = ((uint32_t)ee[0] << 24) | ((uint32_t)ee[1] << 16) |
        ((uint32_t)ee[2] << 8) | ee[3];
    /* Duas contas, como tudo o que sai ao host desde a fase 6. O R4 so
     * devolve um bit, e um bit e o alvo mais facil de uma falha induzida:
     * um glitch na comparacao final trocaria "nao confere" por "confere".
     * As duas execucoes sao completas (exponenciacao e comparacao), e so
     * o acordo entre elas vale. Discordou: 91 e erro grave marcado. */
    v  = rsa_verifica(n, e, digest, s);
    v2 = rsa_verifica(n, e, digest, s);
    if (v != v2) {
        erro_grave_marca();
        return ASCII_ERRO_GRAVE;
    }
    if (v < 0) {
        return ASCII_PARAM;
    }
    return (v == 1) ? ASCII_OK : ASCII_VERIF_FALHOU;
}

/* E0 -- gerar par de ECDSA P-256: exportabilidade(1) -> key block da
 *       chave privada (sob a LMK) . Qx(64) . Qy(64)
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao, como o K0 e o R0.
 *   em laco      cada chamada gasta entropia e devolve um par novo. A
 *                chave privada so sai embrulhada; a publica e publica.
 *   exportacao   o campo vai para o cabecalho do bloco, autenticado.
 *   log          sim, antes.
 *
 * A chave privada e sorteada por rejeicao (FIPS 186-5, A.2.2), e o par
 * assina e verifica antes de sair. Erro 91 se esse teste reprovar.
 *
 * FRONTEIRA: dentro. A chave nasce e e embrulhada no keystore. */
static uint8_t h_e0(leitor_t *in, escritor_t *out)
{
    uint32_t bn = 0u;
    uint8_t  exp;
    uint8_t  q[EC_PUB];
    int      v;

    if (((uint32_t)in->pos + 1u) > in->n) {
        return ASCII_MALFORMADA;
    }
    exp = in->p[in->pos];
    in->pos = (uint16_t)(in->pos + 1u);
    if (fim(in) != ASCII_OK) {
        return ASCII_MALFORMADA;
    }
    if ((uint32_t)out->n + TR31_ASCII_EC + 2u * EC_PUB > out->max) {
        return ASCII_INTERNO;
    }
    if (primeiro_uso(KAT_FALHA_ECDSA) != ASCII_OK) {
        return ASCII_ERRO_GRAVE;
    }
    v = keystore_ec_gera(exp, (char *)&out->p[out->n],
                         (uint32_t)(out->max - out->n), &bn, q);
    if (v == -2) { return ASCII_ERRO_GRAVE; }
    if (v != 0)  { return (exp == 'E' || exp == 'N' || exp == 'S') ? ASCII_INTERNO
                                                                  : ASCII_PARAM; }
    out->n = (uint16_t)(out->n + bn);
    poe_hex(out, q, EC_PUB);
    return ASCII_OK;
}

/* E2 -- assinar com ECDSA P-256: key block da chave privada (sob a LMK) .
 *       digest(64) -> r(64) . s(64)
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao.
 *   em laco      e um oraculo de assinatura, que e o servico. O numero
 *                secreto k de cada assinatura sai do DRBG e nunca se
 *                repete; a multiplicacao de ponto tem tempo constante. A
 *                assinatura e verificada antes de sair.
 *   exportacao   nao se aplica: a chave nao sai, e o bloco ja e do host.
 *   log          sim, antes.
 *
 * Erros: 10 bloco invalido, 11 bloco de outro tipo de chave, 91 a
 * verificacao reprovou (nada sai, erro grave marcado).
 *
 * FRONTEIRA: dentro. A chave abre no keystore e fica la; o despachante a
 * apaga no fim do comando. */
static uint8_t h_e2(leitor_t *in, escritor_t *out)
{
    const uint8_t *b = 0;
    uint16_t       bn = 0u;
    uint8_t        digest[EC_BYTES], sig[EC_SIG];
    uint8_t        r;
    int            v;

    if ((r = le_bloco(in, &b, &bn)) != ASCII_OK)          { return r; }
    if ((r = le_hex(in, digest, EC_BYTES)) != ASCII_OK)   { return r; }
    if ((r = fim(in)) != ASCII_OK)                        { return r; }
    if ((r = primeiro_uso(KAT_FALHA_ECDSA)) != ASCII_OK)  { return r; }

    v = keystore_ec_abre((const char *)b, bn);
    if (v == -3) { return ASCII_MODO; }
    if (v != 0)  { return ASCII_BLOCO_INVAL; }

    v = keystore_ec_assina(digest, sig);
    if (v == -2) { return ASCII_ERRO_GRAVE; }
    if (v != 0)  { return ASCII_INTERNO; }
    poe_hex(out, sig, EC_SIG);
    return ASCII_OK;
}

/* E4 -- verificar assinatura ECDSA P-256: Qx(64) . Qy(64) . digest(64) .
 *       r(64) . s(64). Erro 01 se nao confere, 16 se a chave publica nao
 *       e um ponto da curva.
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao, e nao usa chave nenhuma do dispositivo.
 *   em laco      so dados publicos entram, e sai um bit.
 *   exportacao   nao se aplica.
 *   log          sim, antes de executar, como o R4.
 */
static uint8_t h_e4(leitor_t *in, escritor_t *out)
{
    uint8_t q[EC_PUB], digest[EC_BYTES], sig[EC_SIG];
    uint8_t r;
    int     v, v2;

    (void)out;
    if ((r = le_hex(in, q, EC_PUB)) != ASCII_OK)          { return r; }
    if ((r = le_hex(in, digest, EC_BYTES)) != ASCII_OK)   { return r; }
    if ((r = le_hex(in, sig, EC_SIG)) != ASCII_OK)        { return r; }
    if ((r = fim(in)) != ASCII_OK)                        { return r; }
    if ((r = primeiro_uso(KAT_FALHA_ECDSA)) != ASCII_OK)  { return r; }

    /* Duas contas completas, como no R4: um bit e o alvo mais facil de
     * uma falha induzida. Discordou: 91 e erro grave marcado. */
    v  = ecdsa_verifica(q, digest, sig);
    v2 = ecdsa_verifica(q, digest, sig);
    if (v != v2) {
        erro_grave_marca();
        return ASCII_ERRO_GRAVE;
    }
    if (v < 0) {
        return ASCII_PARAM;
    }
    return (v == 1) ? ASCII_OK : ASCII_VERIF_FALHOU;
}

/* K4 -- exportar sob KEK: bloco da KEK . bloco da chave (os dois sob a
 *       LMK) -> bloco da chave sob a KEK . KCV(6)
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao. A KEK em si entrou por cerimonia
 *                (componentes, no console) -- e ali que fica o controle.
 *   vazamento    em laco, a mesma chave sai sob a KEK com enchimento
 *                novo a cada vez; nada que o primeiro bloco ja nao desse.
 *                Quem tem o bloco da KEK e o da chave pode mandar a chave
 *                para quem tem a KEK -- e o servico, e e por isso que a
 *                KEK existe.
 *   exportability SIM, e aqui ela decide de verdade: 'N' e recusado com
 *                12, dentro do key store, pela mesma regra do console. O
 *                bloco de saida leva o cabecalho de entrada, 'N' nunca.
 *   log          sim, antes.
 *
 * A KEK precisa de uso 'K0' (senao 13) e modo 'E' ou 'B' (senao 11). */
static uint8_t h_k4(leitor_t *in, escritor_t *out)
{
    const uint8_t *kb = 0, *cb = 0;
    uint16_t       kbn = 0u, cbn = 0u;
    uint8_t        kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    char           bloco[TR31_ASCII_MAX];
    uint32_t       bn = 0u, i;
    ks_info_t      info;
    uint8_t        r;
    int            v;

    if ((r = le_bloco(in, &kb, &kbn)) != ASCII_OK) { return r; }
    if ((r = le_bloco(in, &cb, &cbn)) != ASCII_OK) { return r; }
    if ((r = fim(in)) != ASCII_OK)                 { return r; }

    if ((r = kek_subchaves(kb, kbn, KS_MODO_CIFRA, kbek, kbak)) != ASCII_OK) {
        goto sai;
    }
    if ((r = abre_bloco(cb, cbn, &info)) != ASCII_OK) {
        goto sai;
    }
    v = keystore_embrulha_kek(KS_HANDLE_EFEMERA, kbek, kbak, bloco, &bn);
    if (v != 0) {
        r = (v == -2) ? ASCII_NAO_EXPORTA : ASCII_INTERNO;
        goto sai;
    }
    for (i = 0u; i < bn; i++) {
        poe(out, (uint8_t)bloco[i]);
    }
    poe_hex(out, info.kcv, KS_KCV_LEN);
    r = ASCII_OK;
sai:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(bloco, sizeof bloco);
    return r;
}

/* K6 -- importar sob KEK: bloco da KEK (sob a LMK) . bloco da chave (sob
 *       a KEK) -> bloco da chave sob a LMK . KCV(6)
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao, como o K4.
 *   vazamento    bloco recebido invalido -- MAC errado, outra KEK,
 *                malformado -- e 10, um codigo so: o comando e o mais
 *                exposto da porta, como o IMPORT_KEY do console. O KCV so
 *                sai com sucesso.
 *   exportability nao se aplica: o resultado fica sob a LMK, e isso nao e
 *                exportar. Uma chave 'N' recebida precisa poder ser
 *                guardada -- 'N' diz que ela nao segue adiante, e nao
 *                segue: o K4 a recusa.
 *   log          sim, antes.
 *
 * A KEK precisa de uso 'K0' (senao 13) e modo 'D' ou 'B' (senao 11). */
static uint8_t h_k6(leitor_t *in, escritor_t *out)
{
    const uint8_t *kb = 0, *cb = 0;
    uint16_t       kbn = 0u, cbn = 0u;
    uint8_t        kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    char           bloco[TR31_ASCII_MAX];
    uint32_t       bn = 0u, i;
    ks_info_t      info;
    uint8_t        r;

    if ((r = le_bloco(in, &kb, &kbn)) != ASCII_OK) { return r; }
    if ((r = le_bloco(in, &cb, &cbn)) != ASCII_OK) { return r; }
    if ((r = fim(in)) != ASCII_OK)                 { return r; }

    if ((r = kek_subchaves(kb, kbn, KS_MODO_DECIFRA, kbek, kbak))
        != ASCII_OK) {
        goto sai;
    }
    if ((r = abre_sob(kbek, kbak, cb, cbn, &info)) != ASCII_OK) {
        goto sai;
    }
    if (keystore_embrulha_lmk(KS_HANDLE_EFEMERA, bloco, &bn) != 0) {
        r = ASCII_INTERNO;
        goto sai;
    }
    for (i = 0u; i < bn; i++) {
        poe(out, (uint8_t)bloco[i]);
    }
    poe_hex(out, info.kcv, KS_KCV_LEN);
    r = ASCII_OK;
sai:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(bloco, sizeof bloco);
    return r;
}

/* P0 -- traduzir PIN block: bloco da chave de origem . bloco da chave de
 *       destino . formato de origem(1) . formato de destino(1) .
 *       tamanho do PAN(2) . PAN . PIN block(16 ou 32) -> PIN block(16 ou 32)
 *
 * Abre o PIN block com a chave de origem e o fecha sob a de destino. O PIN
 * em claro so existe dentro do key store. Formatos da ISO 9564-1: '0'
 * (3DES, bloco de 16 caracteres hex) e '4' (AES, 32 caracteres). As quatro
 * combinacoes valem: a norma permite traduzir entre o 0 e o 4 nos dois
 * sentidos.
 *
 * O pedido leva UM PAN, que vale para a origem e para o destino. E de
 * proposito: traduzir trocando o PAN amarra o PIN de uma conta a outra
 * conta, e a norma restringe isso. Nao acrescentar um segundo PAN.
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao.
 *   vazamento    o erro 14 diz ao host se o bloco, aberto sob aquela chave
 *                e aquele PAN, e um campo bem formado do formato de origem.
 *                E inerente ao servico: sem isso o host traduziria lixo sem
 *                saber.
 *
 *                Formato 4: um bloco ao acaso passa cerca de uma vez em
 *                2^24 (manual, secao 41.2), e o veredito nao separa um PIN
 *                de outro, porque o PAN entra DEPOIS de uma cifragem.
 *
 *                Formato 0: o veredito VAZA O PIN, e e um ataque publicado
 *                (Clulow, 2003). O PAN entra por
 *                XOR direto sobre os digitos do PIN, do terceiro em diante,
 *                e o PAN vem do host. Com o PAN alterado num digito, o 14
 *                diz se (digito do PIN XOR diferenca) passou de 9. Com
 *                108 pedidos por bloco (9 trocas em 12 posicoes) saem o
 *                tamanho do PIN, sempre, e parte de cada digito: de 10
 *                candidatos sobram 3,9 em media, e 2 quando o digito do
 *                PAN naquela posicao e 8 ou 9 (host/test_pinblock.py faz
 *                a conta). O ultimo bit do digito nunca sai, e os dois
 *                primeiros digitos ficam de fora: o campo do PAN e zero
 *                ali. O equipamento nao tem como fechar isso sem
 *                deixar de falar o formato 0, que e o que o mercado usa;
 *                esconder o 14 atras de outro codigo nao fecha, porque a
 *                resposta continua sendo sucesso ou recusa. O controle e
 *                de fora: o log, que registra cada pedido recusado, e o
 *                limite de quem pode falar com a porta host. Ver o manual,
 *                Parte VII, e doc/fase8-notas.md.
 *
 *                O bloco de saida no formato 4 leva aleatorio novo. No
 *                formato 0 nao ha aleatorio: mesmo PIN, mesmo PAN e mesma
 *                chave dao o mesmo bloco, e o host ve quando uma conta
 *                repete o PIN. E do formato.
 *
 *                O que o comando NAO faz e devolver o PIN, nem aceitar
 *                chave que nao seja P0 -- uma chave de dados aqui seria o
 *                C2 decifrando PINs.
 *   exportability nao se aplica: nenhuma chave sai.
 *   log          sim, antes.
 *
 * As duas chaves precisam de uso 'P0' e do algoritmo do formato (AES para o
 * 4, 3DES para o 0), senao 11; a de origem, modo 'D' ou 'B'; a de destino,
 * 'E' ou 'B' (senao 11). */
static uint8_t pan_dos_dois(const uint8_t *pan, uint32_t n, uint8_t formato,
                            uint8_t campo[PIN_BLOCO])
{
    int v = (formato == (uint8_t)PIN_FORMATO_0)
                ? pinblock_campo_pan0(pan, n, campo)
                : pinblock_campo_pan(pan, n, campo);
    return (v == 0) ? ASCII_OK : ASCII_PARAM;
}

/* Abre o key block da chave de PIN, abre com ela o PIN block, e tira a chave
 * do slot efemero. O PIN fica no key store (g_pin). E o unico lugar que liga
 * o resultado de keystore_pin_abre() a um codigo ASCII: o 14 e o oraculo de
 * formato, e o P0 e os V* tem de responder igual ao mesmo PIN block. */
static uint8_t abre_pin(const uint8_t *kb, uint16_t kbn, uint8_t formato,
                        const uint8_t *pan_campo, const uint8_t *bloco)
{
    ks_info_t info;
    uint8_t   r;
    int       v;

    if ((r = abre_bloco(kb, kbn, &info)) != ASCII_OK) { return r; }
    v = keystore_pin_abre(KS_HANDLE_EFEMERA, formato, pan_campo, bloco);
    keystore_efemera_apaga();
    if (v == 0)  { return ASCII_OK; }
    if (v == -1) { return ASCII_MODO; }
    if (v == -2) { return ASCII_ERRO_GRAVE; }
    return (v == -4) ? ASCII_PIN_INVAL : ASCII_INTERNO;
}

static uint8_t h_p0(leitor_t *in, escritor_t *out)
{
    const uint8_t *ko = 0, *kd = 0;
    uint16_t       kon = 0u, kdn = 0u;
    uint8_t        pan_o[PIN_BLOCO], pan_d[PIN_BLOCO];
    uint8_t        bloco[PIN_BLOCO], saida[PIN_BLOCO];
    ks_info_t      info;
    int32_t        pn;
    uint8_t        fo, fd, r;
    uint32_t       no, nd;
    int            v;

    if ((r = le_bloco(in, &ko, &kon)) != ASCII_OK) { return r; }
    if ((r = le_bloco(in, &kd, &kdn)) != ASCII_OK) { return r; }
    if ((uint32_t)in->pos + 2u > in->n)            { return ASCII_MALFORMADA; }
    fo = in->p[in->pos];
    fd = in->p[in->pos + 1u];
    if (((fo != (uint8_t)PIN_FORMATO_0) && (fo != (uint8_t)PIN_FORMATO_4)) ||
        ((fd != (uint8_t)PIN_FORMATO_0) && (fd != (uint8_t)PIN_FORMATO_4))) {
        return ASCII_PARAM;
    }
    no = (fo == (uint8_t)PIN_FORMATO_0) ? PIN_BLOCO_0 : PIN_BLOCO;
    nd = (fd == (uint8_t)PIN_FORMATO_0) ? PIN_BLOCO_0 : PIN_BLOCO;
    in->pos = (uint16_t)(in->pos + 2u);
    pn = le_dec(in, 2u);
    if (pn == -1)                                  { return ASCII_MALFORMADA; }
    if ((pn < 1) || (pn > (int32_t)PIN_PAN_MAX))   { return ASCII_PARAM; }
    if ((uint32_t)in->pos + (uint32_t)pn > in->n)  { return ASCII_MALFORMADA; }
    /* O campo do PAN de cada lado, no formato daquele lado. O formato 0
     * pede de 13 a 19 digitos. O PAN e dado publico. */
    if ((r = pan_dos_dois(&in->p[in->pos], (uint32_t)pn, fo, pan_o)) != ASCII_OK) {
        return r;
    }
    if ((r = pan_dos_dois(&in->p[in->pos], (uint32_t)pn, fd, pan_d)) != ASCII_OK) {
        return r;
    }
    in->pos = (uint16_t)(in->pos + (uint16_t)pn);
    if ((r = le_hex(in, bloco, no)) != ASCII_OK)        { return r; }
    if ((r = fim(in)) != ASCII_OK)                      { return r; }

    /* Uma chave por vez no slot efemero: a de origem sai antes de a de
     * destino entrar. Entre as duas, o campo do PIN fica no key store. */
    if ((r = abre_pin(ko, kon, fo, pan_o, bloco)) != ASCII_OK) { return r; }
    if ((r = abre_bloco(kd, kdn, &info)) != ASCII_OK)   { return r; }
    v = keystore_pin_fecha(KS_HANDLE_EFEMERA, fd, pan_d, saida);
    if (v != 0) {
        if (v == -1) { return ASCII_MODO; }
        return (v == -2) ? ASCII_ERRO_GRAVE : ASCII_INTERNO;
    }
    poe_hex(out, saida, nd);
    return ASCII_OK;
}

/* ------------------------------------------------------------------ */
/* Verificacao de PIN (fase 8, etapa 8.5)                              */
/* ------------------------------------------------------------------ */

/* V0 -- gerar offset:     COMUM . tabela autorizada(32) . dados de
 *                         validacao(16 hex)  ->  tamanho(2) . offset
 * V2 -- verificar offset: COMUM . tabela autorizada(32) . dados de
 *                         validacao(16 hex) . tamanho(2) . offset
 *                         ->  00 confere, 01 nao confere
 * V4 -- gerar PVV:        COMUM . indice da chave(1)  ->  PVV(4)
 * V6 -- verificar PVV:    COMUM . indice da chave(1) . PVV(4)
 *                         ->  00 confere, 01 nao confere
 *
 *   COMUM = bloco da chave de PIN . bloco da chave de verificacao .
 *           formato(1) . tamanho do PAN(2) . PAN . PIN block(16 ou 32)
 *
 * O PIN chega cifrado, num PIN block, e e aberto dentro do key store; o
 * equipamento nunca recebe PIN em claro. A chave de PIN e a do P0 (uso P0,
 * modo 'D' ou 'B'). A chave de verificacao e 3DES, de uso V1 (offset) ou V2
 * (PVV); gerar pede modo 'G' ou 'C', verificar pede 'V' ou 'C'. Senao, 11.
 *
 * A tabela autorizada sao os 16 digitos da tabela de decimalizacao e os 16
 * caracteres do MAC que o console devolveu (TABELA_AUTORIZA). O MAC amarra a
 * tabela a UMA chave de verificacao, pelo KCV dela. MAC errado, ou MAC feito
 * para outra chave: 17.
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao. Quem tem dual control e a autorizacao da
 *                tabela, no console.
 *   vazamento    V2 e V6 devolvem UM BIT, e e o servico. Com ele, quem tem
 *                um PIN block e escolhe o offset (ou o PVV) acha o offset
 *                certo em ate 10^n tentativas: e a busca que o metodo
 *                admite, e o controle e de fora (contador de tentativas no
 *                sistema do emissor, e o log, que registra cada 01).
 *
 *                O ATALHO e a tabela de decimalizacao (Bond e Zielinski,
 *                2003): com a tabela a escolha do chamador, o bit de V2
 *                entrega um PIN de 4 digitos em 15 pedidos em media, e
 *                conferir a FORMA da tabela nao fecha -- a variante do
 *                offset usa tabelas quase iguais a legitima. Por isso a
 *                tabela so vale com MAC, o host nao fabrica o MAC, e o MAC
 *                vale so para a chave V1 para a qual foi autorizado: duas
 *                tabelas autorizadas para chaves diferentes nao se
 *                combinam.
 *
 *                Os dados de validacao sao do host, e nao sao protegidos.
 *                Troca-los muda o PIN natural para outro valor que o host
 *                tambem nao conhece: nao e atalho.
 *
 *                O 14 e o mesmo oraculo de formato do P0, com o mesmo
 *                custo no formato 0. Ver o comentario de la.
 *
 *                V0 e V4 sao funcoes de EMISSAO. Quem pode chama-las com
 *                um PIN block de PIN conhecido aprende o PIN natural
 *                (PIN - offset), e dai o PIN de qualquer conta de que tenha
 *                o offset. Nao ha conserto dentro do metodo: o offset e
 *                publico por construcao. O controle e o modo da chave: o
 *                bloco entregue a quem so verifica tem modo 'V', e com ele
 *                V0 e V4 respondem 11.
 *
 *                O tamanho do PIN sai em V0, no tamanho do offset. E do
 *                metodo: o offset tem um digito por digito de PIN.
 *   exportability nao se aplica: nenhuma chave sai, e o PIN tambem nao.
 *   log          sim, antes; o 01 fica registrado.
 *
 * FRONTEIRA: dentro. O handler ve o PIN block cifrado, o offset e o PVV,
 * que sao publicos. O PIN e o PIN natural ficam em keystore.c. */
typedef struct {
    const uint8_t *kp, *kv;
    uint16_t       kpn, kvn;
    const uint8_t *pan;
    uint32_t       pan_n;
    uint8_t        formato;
    uint8_t        pan_campo[PIN_BLOCO];
    uint8_t        bloco[PIN_BLOCO];
} pin_pedido_t;

static uint8_t le_pin_pedido(leitor_t *in, pin_pedido_t *p)
{
    int32_t pn;
    uint8_t r;

    if ((r = le_bloco(in, &p->kp, &p->kpn)) != ASCII_OK) { return r; }
    if ((r = le_bloco(in, &p->kv, &p->kvn)) != ASCII_OK) { return r; }
    if ((uint32_t)in->pos + 1u > in->n)            { return ASCII_MALFORMADA; }
    p->formato = in->p[in->pos];
    if ((p->formato != (uint8_t)PIN_FORMATO_0) &&
        (p->formato != (uint8_t)PIN_FORMATO_4)) {
        return ASCII_PARAM;
    }
    in->pos = (uint16_t)(in->pos + 1u);
    pn = le_dec(in, 2u);
    if (pn == -1)                                  { return ASCII_MALFORMADA; }
    if ((pn < 1) || (pn > (int32_t)PIN_PAN_MAX))   { return ASCII_PARAM; }
    if ((uint32_t)in->pos + (uint32_t)pn > in->n)  { return ASCII_MALFORMADA; }
    p->pan   = &in->p[in->pos];
    p->pan_n = (uint32_t)pn;
    if ((r = pan_dos_dois(p->pan, p->pan_n, p->formato, p->pan_campo))
        != ASCII_OK) {
        return r;
    }
    in->pos = (uint16_t)(in->pos + (uint16_t)pn);
    return le_hex(in, p->bloco, (p->formato == (uint8_t)PIN_FORMATO_0)
                                    ? PIN_BLOCO_0 : PIN_BLOCO);
}

/* Abre o PIN no key store e deixa a chave de verificacao no slot efemero.
 * Uma chave por vez: a de PIN sai antes de a outra entrar. */
static uint8_t pin_e_pvk(const pin_pedido_t *p)
{
    ks_info_t info;
    uint8_t   r;

    if ((r = abre_pin(p->kp, p->kpn, p->formato, p->pan_campo, p->bloco))
        != ASCII_OK) {
        return r;
    }
    return abre_bloco(p->kv, p->kvn, &info);
}

/* O codigo ASCII do resultado de keystore_pin_offset() e _pvv(). */
static uint8_t pinv_codigo(int v)
{
    if (v == 0)  { return ASCII_OK; }
    if (v == 1)  { return ASCII_VERIF_FALHOU; }
    if (v == -1) { return ASCII_MODO; }
    if (v == -5) { return ASCII_TABELA; }
    return (v == -2) ? ASCII_ERRO_GRAVE : ASCII_INTERNO;
}

/* Le `n` digitos decimais ASCII. */
static uint8_t le_digitos(leitor_t *in, uint8_t *out, uint32_t n)
{
    uint32_t i;

    if ((uint32_t)in->pos + n > in->n) {
        return ASCII_MALFORMADA;
    }
    for (i = 0u; i < n; i++) {
        uint8_t c = in->p[in->pos + i];
        if ((c < (uint8_t)'0') || (c > (uint8_t)'9')) {
            return ASCII_PARAM;
        }
        out[i] = c;
    }
    in->pos = (uint16_t)(in->pos + n);
    return ASCII_OK;
}

static uint8_t offset_cmd(leitor_t *in, escritor_t *out, int gerar)
{
    pin_pedido_t p;
    uint8_t      tab[PINV_TABELA], mac[KS_TABELA_MAC], dados[PINV_DADOS];
    uint8_t      offset[PIN_MAX];
    uint32_t     n = 0u, i;
    int32_t      v;
    uint8_t      r;

    if ((r = le_pin_pedido(in, &p)) != ASCII_OK)             { return r; }
    if ((r = le_digitos(in, tab, PINV_TABELA)) != ASCII_OK)  { return r; }
    if ((r = le_hex(in, mac, sizeof mac)) != ASCII_OK)       { return r; }
    if ((r = le_hex(in, dados, sizeof dados)) != ASCII_OK)   { return r; }
    if (!gerar) {
        v = le_dec(in, 2u);
        if (v == -1)                                   { return ASCII_MALFORMADA; }
        if ((v < (int32_t)PIN_MIN) || (v > (int32_t)PIN_MAX)) { return ASCII_PARAM; }
        n = (uint32_t)v;
        if ((r = le_digitos(in, offset, n)) != ASCII_OK)     { return r; }
    }
    if ((r = fim(in)) != ASCII_OK)                           { return r; }

    /* A tabela e conferida no key store, contra o KCV da chave de
     * verificacao que entrou no slot: ela so vale para a chave para a qual o
     * console a autorizou. */
    if ((r = pin_e_pvk(&p)) != ASCII_OK)                     { return r; }
    r = pinv_codigo(keystore_pin_offset(KS_HANDLE_EFEMERA, gerar, tab, mac,
                                        dados, offset, &n));
    if (gerar && (r == ASCII_OK)) {
        poe_dec(out, n, 2u);
        for (i = 0u; i < n; i++) {
            poe(out, offset[i]);
        }
    }
    return r;
}

static uint8_t h_v0(leitor_t *in, escritor_t *out) { return offset_cmd(in, out, 1); }
static uint8_t h_v2(leitor_t *in, escritor_t *out) { return offset_cmd(in, out, 0); }

static uint8_t pvv_cmd(leitor_t *in, escritor_t *out, int gerar)
{
    pin_pedido_t p;
    uint8_t      ind[1], pvv[PINV_PVV];
    uint32_t     i;
    uint8_t      r;

    if ((r = le_pin_pedido(in, &p)) != ASCII_OK)             { return r; }
    if ((r = le_digitos(in, ind, 1u)) != ASCII_OK)           { return r; }
    if (!gerar) {
        if ((r = le_digitos(in, pvv, PINV_PVV)) != ASCII_OK) { return r; }
    }
    if ((r = fim(in)) != ASCII_OK)                           { return r; }
    /* O PVV usa 11 digitos do PAN antes do verificador. */
    if (p.pan_n < PINV_PVV_PAN) {
        return ASCII_PARAM;
    }
    if ((r = pin_e_pvk(&p)) != ASCII_OK)                     { return r; }
    r = pinv_codigo(keystore_pin_pvv(KS_HANDLE_EFEMERA, gerar, p.pan, p.pan_n,
                                     (uint8_t)(ind[0] - (uint8_t)'0'), pvv));
    if (gerar && (r == ASCII_OK)) {
        for (i = 0u; i < PINV_PVV; i++) {
            poe(out, pvv[i]);
        }
    }
    return r;
}

static uint8_t h_v4(leitor_t *in, escritor_t *out) { return pvv_cmd(in, out, 1); }
static uint8_t h_v6(leitor_t *in, escritor_t *out) { return pvv_cmd(in, out, 0); }

/* ------------------------------------------------------------------ */
/* CVV, CVV2 e iCVV (etapa 8.6)                                        */
/* ------------------------------------------------------------------ */

/* W0  gerar CVV:     bloco CVK . PAN (2 + n) . validade (4) . codigo de
 *                    servico (3)                       -> CVV (3)
 * W2  verificar CVV: o mesmo . CVV (3)                 -> 00 ou 01
 *
 * Um par de comandos para os tres codigos: CVV (o codigo de servico da
 * tarja), CVV2 (000) e iCVV (999). E o mesmo metodo; o codigo de servico
 * entra na conta. A validade vai como o emissor a usa (AAMM ou MMAA): o
 * equipamento nao a interpreta, e gerar e verificar tem de usar a mesma.
 *
 * Checklist:
 *   estados      OPERATIONAL.
 *   dual control nao: e operacao.
 *   vazamento    W2 devolve UM BIT, e e o servico. Com ele, quem tem o
 *                bloco da chave acha o CVV de um cartao em ate 1000
 *                pedidos: 3 digitos sao pouco. Nao ha conserto dentro do
 *                metodo; o controle e de fora (o emissor conta tentativas
 *                por cartao) e o log, que registra cada 01.
 *
 *                W0 e funcao de EMISSAO: quem a chama tem o CVV de qualquer
 *                PAN, e o CVV2 e o que se pede numa compra sem o cartao. O
 *                controle e o modo da chave: o bloco entregue ao autorizador
 *                tem modo 'V', e com ele W0 responde 11. Uma chave de outro
 *                uso (a de PIN, a de verificacao de PIN) nao calcula CVV, e
 *                a CVK nao serve a outro comando.
 *
 *                O codigo de servico e escolha do chamador. Com uma chave
 *                'C', W0 com 000 da o CVV2 de qualquer cartao de que se
 *                tenha a tarja: e por isso que o emissor separa a chave de
 *                emitir (G) da de autorizar (V).
 *   exportability nao se aplica: nenhuma chave sai.
 *   log          sim, antes; o 01 fica registrado.
 *
 * FRONTEIRA: dentro. O handler ve o PAN, a validade e o CVV, que vem e vao
 * pela porta. A chave e o resultado da cifra ficam em keystore.c. */
static uint8_t cvv_cmd(leitor_t *in, escritor_t *out, int gerar)
{
    const uint8_t *kb, *pan;
    uint16_t       kbn;
    uint8_t        val[CVV_VALIDADE], sc[CVV_SERVICO], cvv[CVV_DIGITOS];
    uint8_t        dados[CVV_DADOS];
    ks_info_t      info;
    int32_t        pn;
    uint32_t       i;
    uint8_t        r;

    if ((r = le_bloco(in, &kb, &kbn)) != ASCII_OK)           { return r; }
    pn = le_dec(in, 2u);
    if (pn == -1)                                            { return ASCII_MALFORMADA; }
    if ((pn < (int32_t)CVV_PAN_MIN) || (pn > (int32_t)CVV_PAN_MAX)) { return ASCII_PARAM; }
    if ((uint32_t)in->pos + (uint32_t)pn > in->n)            { return ASCII_MALFORMADA; }
    pan = &in->p[in->pos];
    in->pos = (uint16_t)(in->pos + (uint16_t)pn);
    if ((r = le_digitos(in, val, CVV_VALIDADE)) != ASCII_OK) { return r; }
    if ((r = le_digitos(in, sc, CVV_SERVICO)) != ASCII_OK)   { return r; }
    if (!gerar) {
        if ((r = le_digitos(in, cvv, CVV_DIGITOS)) != ASCII_OK) { return r; }
    }
    if ((r = fim(in)) != ASCII_OK)                           { return r; }
    if (cvv_dados(pan, (uint32_t)pn, val, sc, dados) != 0)   { return ASCII_PARAM; }

    if ((r = abre_bloco(kb, kbn, &info)) != ASCII_OK)        { return r; }
    r = pinv_codigo(keystore_cvv(KS_HANDLE_EFEMERA, gerar, dados, cvv));
    if (gerar && (r == ASCII_OK)) {
        for (i = 0u; i < CVV_DIGITOS; i++) {
            poe(out, cvv[i]);
        }
    }
    /* O CVV2 e dado sensivel de autenticacao: a copia local nao fica na
     * pilha. Os buffers da mensagem o despachante apaga. */
    wipe(cvv, sizeof cvv);
    return r;
}

static uint8_t h_w0(leitor_t *in, escritor_t *out) { return cvv_cmd(in, out, 1); }
static uint8_t h_w2(leitor_t *in, escritor_t *out) { return cvv_cmd(in, out, 0); }

/* ------------------------------------------------------------------ */
/* Tabela                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t         c0, c1;
    uint32_t        estados;
    ascii_handler_t handler;
    uint8_t         loga;
} ascii_entry_t;

#define L 1u
#define I 0u

/* Nenhum comando de cerimonia nesta tabela, de proposito: carregar
 * componente, mudar estado e zeroizar sao do CONSOLE (protocolo binario).
 * E a separacao de papeis da categoria -- o host opera, nao administra. */
static const ascii_entry_t g_ascii[] = {
    { 'D', '0', ST_NORMAL, h_d0, I },
    { 'K', '0', ST_OPER,   h_k0, L },
    { 'K', '2', ST_OPER,   h_k2, I },
    { 'K', '4', ST_OPER,   h_k4, L },
    { 'K', '6', ST_OPER,   h_k6, L },
    { 'C', '0', ST_OPER,   h_c0, L },
    { 'C', '2', ST_OPER,   h_c2, L },
    { 'M', '0', ST_OPER,   h_m0, L },
    { 'M', '2', ST_OPER,   h_m2, L },
    { 'P', '0', ST_OPER,   h_p0, L },
    { 'V', '0', ST_OPER,   h_v0, L },
    { 'V', '2', ST_OPER,   h_v2, L },
    { 'V', '4', ST_OPER,   h_v4, L },
    { 'V', '6', ST_OPER,   h_v6, L },
    { 'W', '0', ST_OPER,   h_w0, L },
    { 'W', '2', ST_OPER,   h_w2, L },
    { 'R', '0', ST_OPER,   h_r0, L },
    { 'R', '2', ST_OPER,   h_r2, L },
    { 'R', '4', ST_OPER,   h_r4, L },
    { 'E', '0', ST_OPER,   h_e0, L },
    { 'E', '2', ST_OPER,   h_e2, L },
    { 'E', '4', ST_OPER,   h_e4, L },
};

#undef L
#undef I

#define N_ASCII (sizeof(g_ascii) / sizeof(g_ascii[0]))

/* ------------------------------------------------------------------ */
/* Despacho                                                            */
/* ------------------------------------------------------------------ */

void ascii_despacha(const uint8_t *msg, uint16_t n,
                    uint8_t *resp, uint16_t resp_max, uint16_t *resp_n)
{
    escritor_t           w;
    leitor_t             r;
    const ascii_entry_t *e = 0;
    uint32_t             i, seq = 0u;
    int                  logado = 0;
    uint8_t              erro;

    w.p = resp;  w.max = resp_max;  w.n = 0u;  w.estouro = 0u;

    /* Cabecalho: devolvido como veio. Mensagem curta demais para ter
     * comando volta com o que houver, completado com '0'. */
    for (i = 0u; i < ASCII_CAB_LEN; i++) {
        poe(&w, (i < n) ? msg[i] : (uint8_t)'0');
    }
    if (n < ASCII_MIN_LEN) {
        poe(&w, 'Z');
        poe(&w, 'Z');
        poe_dec(&w, ASCII_MALFORMADA, 2u);
        *resp_n = w.n;
        return;
    }

    /* Resposta = comando com o segundo caractere + 1. */
    poe(&w, msg[4]);
    poe(&w, (uint8_t)(msg[5] + 1u));
    poe(&w, '0');                        /* erro: escrito no fim */
    poe(&w, '0');

    for (i = 0u; i < N_ASCII; i++) {
        if ((g_ascii[i].c0 == msg[4]) && (g_ascii[i].c1 == msg[5])) {
            e = &g_ascii[i];
            break;
        }
    }

    if (e == 0) {
        erro = ASCII_DESCONHECIDO;
    } else {
        /* Log ANTES do estado e do handler, como no console: a tentativa
         * fora de hora tambem e evento. O registro guarda os dois
         * caracteres do comando (comando, argumento); os opcodes binarios
         * vao ate 0x2F, entao nao ha colisao. Sem registro, sem execucao. */
        erro = ASCII_OK;
        if (e->loga) {
            if (log_registra(e->c0, (uint8_t)state_get(), e->c1, &seq) == 0) {
                logado = 1;
            } else {
                erro = ASCII_LOG;
            }
        }
        if (erro == ASCII_OK) {
            if ((e->estados & state_mask()) == 0u) {
                erro = ASCII_ESTADO;
            } else {
                r.p = msg;  r.n = n;  r.pos = ASCII_MIN_LEN;
                erro = e->handler(&r, &w);
            }
        }
    }

    if (w.estouro) {
        erro = ASCII_INTERNO;
    }
    /* Campos so com sucesso. Um handler que falhou no meio pode ter
     * escrito metade da resposta -- e meia resposta parece resposta. */
    if (erro != ASCII_OK) {
        w.n = ASCII_MIN_LEN + 2u;
    }
    resp[ASCII_MIN_LEN]      = (uint8_t)('0' + erro / 10u);
    resp[ASCII_MIN_LEN + 1u] = (uint8_t)('0' + erro % 10u);

    if (logado) {
        (void)log_resultado(seq, erro);
    }

    /* Nada da chave do comando sobrevive a ele: o slot efemero, o
     * coprocessador e os buffers de dados. Em QUALQUER desfecho. */
    keystore_efemera_apaga();
    keystore_pin_apaga();
    wipe(g_dados, sizeof g_dados);
    wipe(g_res, sizeof g_res);

    *resp_n = w.n;
}
