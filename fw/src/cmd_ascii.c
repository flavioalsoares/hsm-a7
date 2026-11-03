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
#include "aes_modos.h"
#include "audit_log.h"
#include "cmac.h"
#include "drbg.h"
#include "hsm_cfs.h"
#include "keystore.h"
#include "state.h"
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
    if ((v < (int32_t)TR31_CAB_LEN) || (v > (int32_t)TR31_ASCII_MAX)) {
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

/* Abre o bloco sob a LMK e instala a chave no slot efemero.
 *
 * FRONTEIRA: dentro. `chave`, `kbek` e `kbak` existem na pilha so durante
 * esta funcao e saem zerados. Malformado, MAC errado, feito sob outra LMK
 * ou com cabecalho que o key store recusa: tudo e ASCII_BLOCO_INVAL --
 * distinguir seria o oraculo de padding (ver IMPORT_KEY em cmd.c). */
static uint8_t abre_bloco(const uint8_t *b, uint16_t bn, ks_info_t *info)
{
    uint8_t    kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t    chave[TR31_CHAVE_MAX];
    uint8_t    klen = 0u;
    tr31_cab_t cab;
    uint8_t    r = ASCII_INTERNO;

    if (lmk_deriva_kb(kbek, kbak) != 0) {
        goto sai;
    }
    if (tr31_desembrulha(kbek, kbak, (const char *)b, bn,
                         &cab, chave, &klen) != 0) {
        r = ASCII_BLOCO_INVAL;
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
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    return r;
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
    poe_dec(out, 0u, 2u);               /* major */
    poe_dec(out, 1u, 2u);               /* minor */
    poe_dec(out, 0u, 2u);               /* patch */
    return ASCII_OK;
}

/* K0 -- gerar chave: uso(2) . modo(1) . exportabilidade(1)
 *       -> key block sob a LMK . KCV(6)
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
    uint8_t    r = ASCII_INTERNO;
    uint32_t   i;

    if (((uint32_t)in->pos + 4u) > in->n) {
        return ASCII_MALFORMADA;
    }
    uso[0] = in->p[in->pos];
    uso[1] = in->p[in->pos + 1u];
    modo   = in->p[in->pos + 2u];
    exp    = in->p[in->pos + 3u];
    in->pos = (uint16_t)(in->pos + 4u);
    if (fim(in) != ASCII_OK) {
        return ASCII_MALFORMADA;
    }

    if (drbg_dispositivo_bytes(chave, KS_KEY_MAX) != 0) {
        goto sai;
    }
    if (keystore_efemera(uso, KS_ALG_AES, modo, exp, chave, KS_KEY_MAX)
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
    cab.algoritmo       = KS_ALG_AES;
    cab.modo            = modo;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = exp;
    if (tr31_embrulha(kbek, kbak, &cab, chave, KS_KEY_MAX,
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

    if (keystore_usa_aes(KS_HANDLE_EFEMERA,
                         cifrar ? (uint8_t)KS_MODO_CIFRA
                                : (uint8_t)KS_MODO_DECIFRA) != 0) {
        return ASCII_MODO;
    }
    if (aes_cbc(iv, g_dados, g_res, n, cifrar) != 0) {
        return ASCII_INTERNO;
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

    if (keystore_cmac(KS_HANDLE_EFEMERA, (n > 0u) ? g_dados : 0, n, tag)
        != 0) {
        return ASCII_MODO;
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
    if (v < 0) {
        return ASCII_MODO;
    }
    return (v == 1) ? ASCII_OK : ASCII_VERIF_FALHOU;
}

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
    { 'C', '0', ST_OPER,   h_c0, L },
    { 'C', '2', ST_OPER,   h_c2, L },
    { 'M', '0', ST_OPER,   h_m0, L },
    { 'M', '2', ST_OPER,   h_m2, L },
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
    wipe(g_dados, sizeof g_dados);
    wipe(g_res, sizeof g_res);

    *resp_n = w.n;
}
