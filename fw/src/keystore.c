/* fw/src/keystore.c -- key store em BRAM
 *
 * FRONTEIRA: dentro, e é o bloco mais sensível do firmware. Ver o
 * cabeçalho de keystore.h para as decisões de projeto.
 */
#include "keystore.h"
#include "cmac.h"
#include "drbg.h"
#include "aes_modos.h"
#include "hsm_cfs.h"
#include "state.h"
#include "rsa.h"
#include "ecc.h"
#include "tr31.h"
#include "pinblock.h"
#include "pinverif.h"
#include "cvv.h"
#include "des.h"
#include "pkcs8.h"
#include "kat.h"
#include "dukpt.h"
#include "aes128.h"
#include "wipe.h"

/* Slot completo -- com a chave. Este tipo NÃO aparece no header: nada fora
 * deste arquivo consegue declarar uma variável que contenha chave. */
typedef struct {
    uint8_t  em_uso;
    uint8_t  uso[2];
    uint8_t  algoritmo;
    uint8_t  modo;
    uint8_t  exportabilidade;
    uint8_t  key_len;
    uint8_t  chave[KS_KEY_MAX];
    uint8_t  kcv[KS_KCV_LEN];
    uint32_t contador_uso;
} slot_t;

/* Estáticos: vivem na DMEM, que é Block RAM. Regra 2 por construção.
 *
 * O ÚLTIMO elemento é o slot EFÊMERO da porta host (fase 5): a chave que
 * chega num key block ASCII mora ali só durante o comando. Fica DENTRO do
 * vetor de propósito -- o `keystore_init()` e a prova de zeroização varrem
 * `sizeof g_slots`, e o cobrem sem ninguém lembrar. Os laços que listam,
 * contam e persistem vão só até KS_N_SLOTS, e não o veem. */
#define EFEMERA  KS_N_SLOTS
static slot_t  g_slots[KS_N_SLOTS + 1u];

static uint8_t g_lmk[KS_KEY_MAX];
static uint8_t g_lmk_comps;      /* quantos componentes entraram */
static uint8_t g_lmk_kcv[KS_KCV_LEN];

/* Montagem de chave de TRABALHO por componentes. Separado da LMK de
 * propósito: são chaves com destinos diferentes, e misturar os dois
 * acumuladores seria um caminho para montar uma na região da outra. */
static uint8_t g_comp[KS_KEY_MAX];

/* Fase 7: a chave RSA privada do comando ASCII em curso. Como o slot
 * efemero, existe so durante um comando: entra do key block do host, assina
 * e e apagada pelo despachante no fim de TODO comando. Nunca vai para a
 * flash, e nunca para um slot -- header_valido() recusa o algoritmo 'R'. */
static uint8_t g_rsa[TR31_RSA_CHAVE];
/* O PKCS#8 da chave assimetrica, entre o key block e o formato interno. E
 * chave privada em claro: apagado junto com g_rsa, e varrido na prova. */
static uint8_t g_der[TR31_RSA_DER_MAX];
static uint8_t g_rsa_ok;         /* 0 vazia, ou o algoritmo: 'R' ou 'E'. A
                                  * chave de ECDSA ocupa os 96 primeiros
                                  * bytes da mesma area. */
/* Fase 8: o campo do PIN em claro, entre abrir um PIN block e fecha-lo sob
 * outra chave. E dado sensivel como chave: entra na zeroizacao e na prova. */
static uint8_t g_pin[PIN_BLOCO];
static uint8_t g_pin_ok;

static uint8_t g_comp_n;         /* quantos entraram  */
static uint8_t g_comp_total;     /* quantos foram anunciados */
static uint8_t g_comp_alg;       /* etapa 8.7: 'A' ou 'T', fixado no 0 */
static uint8_t g_comp_len;       /* 32, ou 16 / 24 para 3DES */

/* Uma so fonte de verdade: o host e a tabela de comandos precisam do mesmo
 * numero, e um `3` repetido em dois arquivos e um `4` pela metade esperando
 * acontecer. */
#define LMK_N_COMPONENTES  KS_LMK_N_COMPONENTES

/* ------------------------------------------------------------------ */

int keystore_kcv(const uint8_t *chave, uint8_t key_len, uint8_t out[KS_KCV_LEN])
{
    uint8_t zero[HSM_AES_BLOCK_LEN];
    uint8_t cifrado[HSM_AES_BLOCK_LEN];
    uint8_t i;
    int     r = 0;

    if (key_len != KS_KEY_MAX) {
        return -1;                      /* AES-256, e só */
    }
    for (i = 0u; i < HSM_AES_BLOCK_LEN; i++) {
        zero[i] = 0x00u;
    }

    if (hsm_cfs_aes_key(chave) != 0) {
        r = -1;
    } else if (hsm_cfs_aes_block(zero, cifrado, 1) != 0) {
        r = -1;
    } else {
        for (i = 0u; i < KS_KCV_LEN; i++) {
            out[i] = cifrado[i];
        }
    }

    /* A chave expandida fica no coprocessador depois da operação. Limpar
     * agora, e não "na próxima vez que alguém carregar chave". */
    (void)hsm_cfs_wipe();
    wipe(cifrado, sizeof cifrado);
    if (r != 0) {
        wipe(out, KS_KCV_LEN);
    }
    return r;
}

/* Handle 1..KS_N_SLOTS -> índice 0..KS_N_SLOTS-1, ou -1. O handle do slot
 * efêmero só resolve enquanto ele está ocupado -- isto é, durante um
 * comando da porta host. Fora dele é um slot vazio como outro qualquer. */
static int indice(ks_handle_t h)
{
    if ((h == KS_HANDLE_INVALIDO) || (h > KS_HANDLE_EFEMERA)) {
        return -1;
    }
    if (!g_slots[h - 1u].em_uso) {
        return -1;
    }
    return (int)(h - 1u);
}

static int header_valido(const uint8_t uso[2], uint8_t algoritmo,
                        uint8_t modo, uint8_t exportabilidade)
{
    /* AES-256, ou 3DES (fase 8). Outro algoritmo seria uma chave que o
     * dispositivo não sabe usar -- pior que recusar, porque pareceria
     * instalada. */
    if ((algoritmo != KS_ALG_AES) && (algoritmo != KS_ALG_TDES)) {
        return 0;
    }
    /* Oito valores, em tres grupos: cifra (E/D/B), MAC (G/V/C) e, desde a
     * etapa 8.8, derivacao ('X', a BDK do DUKPT), mais o 'N' que nao faz
     * nada. Os grupos nao se cruzam, e e isso que fecha a confusao de tipo
     * -- uma chave de cifrar nao autentica, e uma BDK nao cifra. */
    if ((modo != KS_MODO_CIFRA) && (modo != KS_MODO_DECIFRA) &&
        (modo != KS_MODO_AMBOS) && (modo != KS_MODO_NENHUM) &&
        (modo != KS_MODO_GERA) && (modo != KS_MODO_VERIFICA) &&
        (modo != KS_MODO_MAC) && (modo != KS_MODO_DERIVA)) {
        return 0;
    }
    if ((exportabilidade != KS_EXP_SIM) && (exportabilidade != KS_EXP_NAO) &&
        (exportabilidade != KS_EXP_SENSIVEL)) {
        return 0;
    }
    /* Uso: dois caracteres imprimíveis. A norma tem uma tabela fechada, mas
     * recusar código desconhecido aqui impediria importar key block válido
     * de outro sistema. Guardar o que veio e deixar a política decidir. */
    if ((uso[0] < 0x20u) || (uso[0] > 0x7Eu) ||
        (uso[1] < 0x20u) || (uso[1] > 0x7Eu)) {
        return 0;
    }
    return 1;
}

/* Apaga TUDO: os 16 slots e a LMK. Unica implementacao de zeroizacao
 * deste modulo -- `lmk_zeroiza()` e o comando ZEROIZE passam por aqui.
 *
 * Varre a area como BYTES CRUS, e nao campo a campo. Duas razoes, e a
 * segunda e a que decide:
 *
 *   1. um campo novo em slot_t entra ja zerado, sem ninguem lembrar;
 *   2. os bytes de PREENCHIMENTO da struct tambem sao apagados -- e e
 *      isso que torna possivel PROVAR a zeroizacao varrendo a regiao byte
 *      a byte. Com padding intocado, a varredura leria lixo indeterminado
 *      e a prova nao valeria nada.
 *
 * `em_uso == 0` e "slot livre", entao tudo zero e um key store vazio e
 * valido: a zeroizacao nao precisa de um passo de "remarcar como livre"
 * que pudesse falhar sozinho. */
void keystore_init(void)
{
    wipe_padrao(g_slots, sizeof g_slots);
    wipe_padrao(g_lmk, sizeof g_lmk);
    wipe_padrao(g_lmk_kcv, sizeof g_lmk_kcv);
    g_lmk_comps = 0u;

    /* O acumulador de componentes também é material de chave: uma
     * montagem interrompida deixaria partes de uma chave de trabalho
     * vivas na BRAM depois de um zeroize. */
    wipe_padrao(g_comp, sizeof g_comp);
    g_comp_n     = 0u;
    g_comp_total = 0u;
    g_comp_alg   = 0u;
    g_comp_len   = 0u;
    wipe_padrao(g_rsa, sizeof g_rsa);
    wipe_padrao(g_der, sizeof g_der);
    g_rsa_ok = 0u;
    wipe_padrao(g_pin, sizeof g_pin);
    g_pin_ok = 0u;

    /* A chave expandida do coprocessador tambem e material de chave, e
     * fica fora da DMEM. Zeroizar so a DMEM deixaria a ultima chave usada
     * viva no aes_key_mem do fabric. */
    (void)hsm_cfs_wipe();
}

/* PROVA da zeroizacao: 1 se nao sobrou um byte diferente de zero em
 * nenhuma das regioes de chave.
 *
 * ⚠ `volatile` nao e enfeite. Sem ele o compilador pode PROVAR que acabou
 * de zerar esta memoria e dobrar a varredura inteira para `return 1` --
 * e a prova viraria uma constante que passa sempre, inclusive quando a
 * zeroizacao falhou. O `volatile` obriga a leitura a acontecer.
 *
 * Acumula com OR em vez de sair no primeiro byte nao-zero: tempo
 * constante, e aqui isso importa pouco, mas o habito de nao ramificar
 * sobre conteudo de memoria de chave e barato. */
int keystore_prova_zeroizacao(void)
{
    const volatile uint8_t *p;
    uint32_t                i;
    uint8_t                 acc = 0u;

    p = (const volatile uint8_t *)(const void *)g_slots;
    for (i = 0u; i < (uint32_t)sizeof g_slots; i++) {
        acc |= p[i];
    }
    p = (const volatile uint8_t *)(const void *)g_lmk;
    for (i = 0u; i < (uint32_t)sizeof g_lmk; i++) {
        acc |= p[i];
    }
    p = (const volatile uint8_t *)(const void *)g_lmk_kcv;
    for (i = 0u; i < (uint32_t)sizeof g_lmk_kcv; i++) {
        acc |= p[i];
    }
    /* O acumulador de componentes entra na prova pelo mesmo motivo que
     * entra na zeroização: é material de chave. Uma montagem interrompida
     * deixaria partes de uma chave viva, e a varredura não veria. */
    p = (const volatile uint8_t *)(const void *)g_comp;
    for (i = 0u; i < (uint32_t)sizeof g_comp; i++) {
        acc |= p[i];
    }
    p = (const volatile uint8_t *)(const void *)g_rsa;
    for (i = 0u; i < (uint32_t)sizeof g_rsa; i++) {
        acc |= p[i];
    }
    p = (const volatile uint8_t *)(const void *)g_pin;
    for (i = 0u; i < (uint32_t)sizeof g_pin; i++) {
        acc |= p[i];
    }
    acc |= g_pin_ok;
    p = (const volatile uint8_t *)(const void *)g_der;
    for (i = 0u; i < (uint32_t)sizeof g_der; i++) {
        acc |= p[i];
    }
    acc |= g_rsa_ok;
    acc |= g_lmk_comps;
    acc |= g_comp_n;
    acc |= g_comp_total;
    acc |= g_comp_alg;
    acc |= g_comp_len;

    return (acc == 0u) ? 1 : 0;
}

int keystore_zeroiza_tudo(void)
{
    keystore_init();
    return keystore_prova_zeroizacao() ? 0 : -1;
}

/* KCV de uma chave 3DES: os 3 primeiros bytes de cifrar 8 zeros com ela.
 *
 * FRONTEIRA: dentro. As subchaves saem apagadas. */
static int kcv_tdes(const uint8_t *chave, uint8_t key_len,
                    uint8_t out[KS_KCV_LEN])
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t  zero[DES_BLOCO] = { 0u };
    uint8_t  cifrado[DES_BLOCO];
    uint32_t i;
    int      r = -1;

    if (tdes_prepara(ctx, chave, key_len) == 0) {
        tdes_bloco(ctx, zero, cifrado, 1);
        for (i = 0u; i < KS_KCV_LEN; i++) {
            out[i] = cifrado[i];
        }
        r = 0;
    }
    tdes_apaga(ctx);
    wipe(cifrado, sizeof cifrado);
    return r;
}

/* KCV de uma chave AES-128 (etapa 8.8b): AES-128 sobre um bloco de zeros,
 * os 3 primeiros bytes, como o da AES-256. Pelo motor em C (aes128.c): o
 * coprocessador so faz AES-256. FRONTEIRA: dentro. */
static int kcv_aes128(const uint8_t chave[AES128_CHAVE], uint8_t out[KS_KCV_LEN])
{
    aes128_ctx_t *ctx = aes128_ctx_comum();
    uint8_t  zero[AES128_BLOCO] = { 0u };
    uint8_t  cifrado[AES128_BLOCO];
    uint32_t i;
    int      r = -1;

    if (aes128_prepara(ctx, chave) == 0) {
        aes128_bloco(ctx, zero, cifrado, 1);
        for (i = 0u; i < KS_KCV_LEN; i++) {
            out[i] = cifrado[i];
        }
        r = 0;
    }
    aes128_apaga(ctx);
    wipe(cifrado, sizeof cifrado);
    return r;
}

/* 1 se o cabecalho permite uma chave AES-128: so a BDK do DUKPT AES (uso B0,
 * modo 'X'), decisao do usuario de 2026-11-22. Qualquer outra chave AES
 * deste equipamento e AES-256, porque o coprocessador so faz AES-256 -- uma
 * chave de dados AES-128 pareceria instalada e nao cifraria certo. */
static int aes128_permitida(const uint8_t uso[2], uint8_t modo)
{
    return (uso[0] == (uint8_t)KS_USO_BDK[0]) &&
           (uso[1] == (uint8_t)KS_USO_BDK[1]) &&
           (modo == KS_MODO_DERIVA);
}

/* Instala no indice `i` (0..15), que o chamador garante livre. E o miolo
 * de keystore_instala() e da restauracao do registro persistente -- a
 * restauracao precisa devolver cada chave ao MESMO slot, porque o host
 * guarda handles. */
static ks_handle_t instala_em(uint32_t i, const uint8_t uso[2],
                              uint8_t algoritmo, uint8_t modo,
                              uint8_t exportabilidade,
                              const uint8_t *chave, uint8_t key_len)
{
    uint8_t  kcv[KS_KCV_LEN];
    slot_t  *s;

    if ((i > EFEMERA) || g_slots[i].em_uso || (chave == 0)) {
        return KS_HANDLE_INVALIDO;
    }
    if (!header_valido(uso, algoritmo, modo, exportabilidade)) {
        return KS_HANDLE_INVALIDO;
    }
    if (algoritmo == KS_ALG_TDES) {
        /* Chave 3DES: comprimento duplo ou triplo. Desde a etapa 8.7 vale
         * em qualquer slot: a chave de troca 3DES nasce por componentes no
         * console e persiste na flash. O que a impede de cifrar dado ou
         * fazer MAC AES sao uso_dados() e uso_mac(), que exigem AES. */
        if (((key_len != TDES_CHAVE_2) && (key_len != TDES_CHAVE_3)) ||
            (kcv_tdes(chave, key_len, kcv) != 0)) {
            wipe(kcv, sizeof kcv);
            return KS_HANDLE_INVALIDO;
        }
    } else if (key_len == AES128_CHAVE) {
        /* AES-128: so a BDK do DUKPT AES (etapa 8.8b). */
        if (!aes128_permitida(uso, modo) || (kcv_aes128(chave, kcv) != 0)) {
            wipe(kcv, sizeof kcv);
            return KS_HANDLE_INVALIDO;
        }
    } else if ((key_len != KS_KEY_MAX) ||
               (keystore_kcv(chave, key_len, kcv) != 0)) {
        wipe(kcv, sizeof kcv);
        return KS_HANDLE_INVALIDO;
    }

    s = &g_slots[i];
    for (uint8_t k = 0u; k < key_len; k++) {
        s->chave[k] = chave[k];
    }
    for (uint8_t k = 0u; k < KS_KCV_LEN; k++) {
        s->kcv[k] = kcv[k];
    }
    s->uso[0]          = uso[0];
    s->uso[1]          = uso[1];
    s->algoritmo       = algoritmo;
    s->modo            = modo;
    s->exportabilidade = exportabilidade;
    s->key_len         = key_len;
    s->contador_uso    = 0u;
    s->em_uso          = 1u;

    wipe(kcv, sizeof kcv);
    return (ks_handle_t)(i + 1u);
}

ks_handle_t keystore_instala(const uint8_t uso[2], uint8_t algoritmo,
                             uint8_t modo, uint8_t exportabilidade,
                             const uint8_t *chave, uint8_t key_len)
{
    uint32_t i;

    for (i = 0u; i < KS_N_SLOTS; i++) {
        if (!g_slots[i].em_uso) {
            break;
        }
    }
    if (i == KS_N_SLOTS) {
        return KS_HANDLE_INVALIDO;       /* cheio */
    }
    return instala_em(i, uso, algoritmo, modo, exportabilidade,
                      chave, key_len);
}

int keystore_apaga(ks_handle_t h)
{
    int i = indice(h);
    if (i < 0) {
        return -1;
    }
    /* Sobrescreve a chave com barreira. Marcar `em_uso = 0` e deixar os
     * bytes lá seria teatro: o slot seria reusado e o material anterior
     * estaria em BRAM até alguém escrever por cima. */
    wipe(g_slots[i].chave, KS_KEY_MAX);
    wipe(g_slots[i].kcv, KS_KCV_LEN);
    g_slots[i].em_uso          = 0u;
    g_slots[i].uso[0]          = 0u;
    g_slots[i].uso[1]          = 0u;
    g_slots[i].algoritmo       = 0u;
    g_slots[i].modo            = 0u;
    g_slots[i].exportabilidade = 0u;
    g_slots[i].key_len         = 0u;
    g_slots[i].contador_uso    = 0u;
    return 0;
}

/* Fase 5 -- a chave de UM comando da porta host. Ver keystore.h. */
ks_handle_t keystore_efemera(const uint8_t uso[2], uint8_t algoritmo,
                             uint8_t modo, uint8_t exportabilidade,
                             const uint8_t *chave, uint8_t key_len)
{
    keystore_efemera_apaga();
    return instala_em(EFEMERA, uso, algoritmo, modo, exportabilidade,
                      chave, key_len);
}

void keystore_efemera_apaga(void)
{
    (void)keystore_apaga(KS_HANDLE_EFEMERA);
    keystore_rsa_apaga();
    /* O coprocessador pode ter ficado com a chave expandida. */
    (void)hsm_cfs_wipe();
}

uint8_t keystore_livres(void)
{
    uint32_t i;
    uint8_t  n = 0u;

    for (i = 0u; i < KS_N_SLOTS; i++) {
        if (!g_slots[i].em_uso) {
            n++;
        }
    }
    return n;
}

int keystore_info(ks_handle_t h, ks_info_t *out)
{
    int i = indice(h);
    if ((i < 0) || (out == 0)) {
        return -1;
    }
    out->em_uso          = g_slots[i].em_uso;
    out->uso[0]          = g_slots[i].uso[0];
    out->uso[1]          = g_slots[i].uso[1];
    out->algoritmo       = g_slots[i].algoritmo;
    out->modo            = g_slots[i].modo;
    out->exportabilidade = g_slots[i].exportabilidade;
    out->key_len         = g_slots[i].key_len;
    out->kcv[0]          = g_slots[i].kcv[0];
    out->kcv[1]          = g_slots[i].kcv[1];
    out->kcv[2]          = g_slots[i].kcv[2];
    out->contador_uso    = g_slots[i].contador_uso;
    return 0;
}

/* 1 se o `uso` do slot é o de chave de dados.
 *
 * O `modo` diz o que a chave pode fazer; o `uso` diz o que ela É, e os dois
 * têm de concordar com o serviço pedido. Sem isto uma KEK, uma chave de PIN
 * ou uma BDK de modo 'B' decifrariam "dados" -- que é a confusão de tipo de
 * chave na forma clássica: quem decifra com a chave que protege chaves lê
 * as chaves. Ver doc/fase5-notas.md. */
static int uso_dados(int i)
{
    /* So AES: estas funcoes carregam a chave no coprocessador, que so faz
     * AES-256. Uma chave 3DES de 16 bytes ali seria lida alem do fim. */
    return (g_slots[i].algoritmo == KS_ALG_AES) &&
           (g_slots[i].uso[0] == (uint8_t)KS_USO_DADOS[0]) &&
           (g_slots[i].uso[1] == (uint8_t)KS_USO_DADOS[1]);
}

/* 1 se o `uso` do slot é da família M, chaves de MAC.
 *
 * A família inteira, e não o código exato: decisão do usuário. A norma
 * distingue os M* por algoritmo; aqui só existe CMAC. */
static int uso_mac(int i)
{
    return (g_slots[i].algoritmo == KS_ALG_AES) &&
           (g_slots[i].uso[0] == (uint8_t)KS_USO_MAC[0]);
}

int keystore_usa_aes(ks_handle_t h, uint8_t precisa_modo)
{
    int i = indice(h);
    if (i < 0) {
        return -1;
    }
    if (!uso_dados(i)) {
        return -1;
    }

    /* Separação de uso: uma chave de MAC não cifra, uma chave de cifra não
     * autentica. É a mesma disciplina que o CMAC aplica ao derivar KBEK e
     * KBAK por propósito -- e a falta dela é a origem da família de
     * ataques de confusão de tipo. */
    if (g_slots[i].modo != KS_MODO_AMBOS) {
        if (g_slots[i].modo != precisa_modo) {
            return -1;
        }
    }
    if (g_slots[i].modo == KS_MODO_NENHUM) {
        return -1;
    }

    if (hsm_cfs_aes_key(g_slots[i].chave) != 0) {
        return -1;
    }
    g_slots[i].contador_uso++;
    return 0;
}

/* 1 se o `modo` do slot permite a operacao de MAC pedida.
 *
 * `precisa` e KS_MODO_GERA ou KS_MODO_VERIFICA. 'C' permite as duas; uma
 * chave de cifra nao entra aqui de jeito nenhum, porque nenhum valor do
 * grupo de cifra casa com nenhum do grupo de MAC. */
static int modo_mac_ok(uint8_t modo, uint8_t precisa)
{
    if (modo == KS_MODO_MAC) {
        return 1;
    }
    return (modo == precisa) ? 1 : 0;
}

/* FRONTEIRA: dentro. A segunda cópia é dado em claro de quem decifra, e sai
 * apagada em todo caminho. Ver keystore.h. */
int keystore_cbc_confere(ks_handle_t h, uint8_t precisa_modo,
                         const uint8_t iv[AES_BLOCO], const uint8_t *entrada,
                         uint8_t *saida, uint32_t n, int cifrar)
{
    static uint8_t segunda[KS_CONFERE_MAX];
    int      i = indice(h);
    int      r = 0;
    uint32_t j;
    uint8_t  dif = 0u;

    if ((i < 0) || (n > KS_CONFERE_MAX)) {
        return -3;
    }

    /* A chave é carregada DE NOVO para a segunda execução. Com uma carga só,
     * uma falha na expansão da chave erra as duas do mesmo jeito, e elas
     * concordam: medido na placa. */
    if (keystore_usa_aes(h, precisa_modo) != 0) {
        return -1;
    }
    if (aes_cbc(iv, entrada, saida, n, cifrar) != 0) {
        r = -3;
    } else if (keystore_usa_aes(h, precisa_modo) != 0) {
        r = -3;
    } else if (aes_cbc(iv, entrada, segunda, n, cifrar) != 0) {
        r = -3;
    } else {
        g_slots[i].contador_uso--;    /* um pedido, um uso */
        for (j = 0u; j < n; j++) {
            dif |= (uint8_t)(saida[j] ^ segunda[j]);
        }
        if (dif != 0u) {
            erro_grave_marca();
            r = -2;
        }
    }

    wipe(segunda, sizeof segunda);
    if (r != 0) {
        wipe(saida, n);
    }
    (void)hsm_cfs_wipe();
    return r;
}

/* ------------------------------------------------------------------ */
/* PIN block (fase 8)                                                  */
/* ------------------------------------------------------------------ */

/* 1 se o `uso` do slot e P0, chave de PIN, e o algoritmo e o do formato:
 * AES para o formato 4, 3DES para o formato 0. O codigo exato do uso: uma
 * chave de dados que abrisse PIN blocks seria o C2 decifrando PINs. */
static int uso_pin(int i, uint8_t formato)
{
    uint8_t alg = (formato == (uint8_t)PIN_FORMATO_0) ? (uint8_t)KS_ALG_TDES
                                                      : (uint8_t)KS_ALG_AES;
    if ((formato != (uint8_t)PIN_FORMATO_0) &&
        (formato != (uint8_t)PIN_FORMATO_4)) {
        return 0;
    }
    return (g_slots[i].algoritmo == alg) &&
           (g_slots[i].uso[0] == (uint8_t)KS_USO_PIN[0]) &&
           (g_slots[i].uso[1] == (uint8_t)KS_USO_PIN[1]);
}

/* Uma passada do formato 4 sob a chave do slot, que e carregada AQUI, a cada
 * chamada. Um bloco de CBC com IV zero e um bloco de AES puro.
 *
 *   cifrar:    saida = E( E(entrada) ^ pan )      entrada = campo do PIN
 *   decifrar:  saida = D( D(entrada) ^ pan )      saida   = campo do PIN
 *
 * FRONTEIRA: dentro. `meio` e um valor intermediario e sai apagado. */
static int pin_passada4(int i, const uint8_t pan[PIN_BLOCO],
                        const uint8_t entrada[PIN_BLOCO],
                        uint8_t saida[PIN_BLOCO], int cifrar)
{
    static const uint8_t zero[AES_BLOCO] = { 0u };
    uint8_t  meio[PIN_BLOCO];
    uint32_t j;
    int      r = -1;

    if (hsm_cfs_aes_key(g_slots[i].chave) == 0) {
        if (aes_cbc(zero, entrada, meio, PIN_BLOCO, cifrar) == 0) {
            for (j = 0u; j < PIN_BLOCO; j++) {
                meio[j] ^= pan[j];
            }
            if (aes_cbc(zero, meio, saida, PIN_BLOCO, cifrar) == 0) {
                r = 0;
            }
        }
    }
    wipe(meio, sizeof meio);
    return r;
}

/* Uma passada do formato 0 sob a chave 3DES do slot. As subchaves sao
 * derivadas AQUI, a cada chamada, e apagadas na saida: e o equivalente de
 * carregar a chave de novo no coprocessador.
 *
 *   cifrar:    saida = E( entrada ^ pan )         entrada = campo do PIN
 *   decifrar:  saida = D( entrada ) ^ pan         saida   = campo do PIN
 *
 * FRONTEIRA: dentro. `meio` e o campo do PIN misturado ao PAN. */
static int pin_passada0_chave(const uint8_t *chave, uint8_t key_len,
                              const uint8_t pan[PIN_BLOCO_0],
                              const uint8_t entrada[PIN_BLOCO_0],
                              uint8_t saida[PIN_BLOCO_0], int cifrar)
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t  meio[PIN_BLOCO_0];
    uint32_t j;
    int      r = -1;

    if (tdes_prepara(ctx, chave, key_len) == 0) {
        if (cifrar) {
            for (j = 0u; j < PIN_BLOCO_0; j++) {
                meio[j] = (uint8_t)(entrada[j] ^ pan[j]);
            }
            tdes_bloco(ctx, meio, saida, 1);
        } else {
            tdes_bloco(ctx, entrada, meio, 0);
            for (j = 0u; j < PIN_BLOCO_0; j++) {
                saida[j] = (uint8_t)(meio[j] ^ pan[j]);
            }
        }
        r = 0;
    }
    tdes_apaga(ctx);
    wipe(meio, sizeof meio);
    return r;
}

/* A passada sob a chave do slot `i`. A etapa 8.8 separou a chave do slot: a
 * chave de PIN do DUKPT nao mora em slot nenhum. FRONTEIRA: dentro. */
static int pin_passada0(int i, const uint8_t pan[PIN_BLOCO_0],
                        const uint8_t entrada[PIN_BLOCO_0],
                        uint8_t saida[PIN_BLOCO_0], int cifrar)
{
    return pin_passada0_chave(g_slots[i].chave, g_slots[i].key_len, pan,
                              entrada, saida, cifrar);
}

/* 1 se o slot e chave de PIN do formato pedido, e o `modo` permite
 * `precisa` (CIFRA/DECIFRA). */
static int pin_pode(int i, uint8_t formato, uint8_t precisa)
{
    if (!uso_pin(i, formato)) {
        return 0;
    }
    return ((g_slots[i].modo == KS_MODO_AMBOS) ||
            (g_slots[i].modo == precisa)) ? 1 : 0;
}

void keystore_pin_apaga(void)
{
    wipe(g_pin, sizeof g_pin);
    g_pin_ok = 0u;
}

/* Abre o bloco uma vez, e deixa em `campo4` o PIN na forma do formato 4.
 * Devolve 0, ou -3 em erro interno. `*valido` diz se o formato confere.
 *
 * FRONTEIRA: dentro. */
static int pin_abre_uma(int i, uint8_t formato, const uint8_t *pan_campo,
                        const uint8_t *bloco, uint8_t campo4[PIN_BLOCO],
                        int *valido)
{
    uint8_t campo0[PIN_BLOCO_0];
    int     r;

    if (formato == (uint8_t)PIN_FORMATO_4) {
        r = pin_passada4(i, pan_campo, bloco, campo4, 0);
        *valido = (r == 0) ? pinblock_campo_valido(campo4) : 0;
        return (r == 0) ? 0 : -3;
    }
    r = pin_passada0(i, pan_campo, bloco, campo0, 0);
    *valido = (r == 0) ? pinblock_f0_para_f4(campo0, campo4) : 0;
    wipe(campo0, sizeof campo0);
    return (r == 0) ? 0 : -3;
}

/* FRONTEIRA: dentro. O campo do PIN em claro fica em g_pin e nas duas copias
 * locais, que saem apagadas em todo caminho. */
int keystore_pin_abre(ks_handle_t h, uint8_t formato,
                      const uint8_t *pan_campo, const uint8_t *bloco)
{
    int      i = indice(h);
    uint8_t  a[PIN_BLOCO], b[PIN_BLOCO];
    uint32_t j;
    uint8_t  dif = 0u;
    int      va = 0, vb = 0;
    int      r;

    keystore_pin_apaga();
    if ((i < 0) || (pan_campo == 0) || (bloco == 0)) {
        return -3;
    }
    if (!pin_pode(i, formato, KS_MODO_DECIFRA)) {
        return -1;
    }
    if ((pin_abre_uma(i, formato, pan_campo, bloco, a, &va) != 0) ||
        (pin_abre_uma(i, formato, pan_campo, bloco, b, &vb) != 0)) {
        r = -3;
    } else {
        for (j = 0u; j < PIN_BLOCO; j++) {
            dif |= (uint8_t)(a[j] ^ b[j]);
        }
        if ((dif != 0u) || (va != vb)) {
            erro_grave_marca();
            r = -2;
        } else if (!va) {
            r = -4;
        } else {
            for (j = 0u; j < PIN_BLOCO; j++) {
                g_pin[j] = a[j];
            }
            g_pin_ok = 1u;
            g_slots[i].contador_uso++;
            r = 0;
        }
    }
    wipe(a, sizeof a);
    wipe(b, sizeof b);
    (void)hsm_cfs_wipe();
    return r;
}

/* Fecha g_pin uma vez sob a chave do slot. FRONTEIRA: dentro. */
static int pin_fecha_uma(int i, uint8_t formato, const uint8_t *pan_campo,
                         uint8_t *bloco)
{
    uint8_t campo0[PIN_BLOCO_0];
    int     r;

    if (formato == (uint8_t)PIN_FORMATO_4) {
        return pin_passada4(i, pan_campo, g_pin, bloco, 1);
    }
    pinblock_f4_para_f0(g_pin, campo0);
    r = pin_passada0(i, pan_campo, campo0, bloco, 1);
    wipe(campo0, sizeof campo0);
    return r;
}

/* FRONTEIRA: dentro ate a ultima linha. O que sai em `bloco` e criptograma. */
int keystore_pin_fecha(ks_handle_t h, uint8_t formato,
                       const uint8_t *pan_campo, uint8_t *bloco)
{
    int      i = indice(h);
    uint8_t  segunda[PIN_BLOCO];
    uint32_t j, tam;
    uint8_t  dif = 0u;
    int      r;

    if ((i < 0) || (pan_campo == 0) || (bloco == 0) || (g_pin_ok == 0u)) {
        keystore_pin_apaga();
        return -3;
    }
    if (!pin_pode(i, formato, KS_MODO_CIFRA)) {
        keystore_pin_apaga();
        return -1;
    }
    tam = (formato == (uint8_t)PIN_FORMATO_0) ? PIN_BLOCO_0 : PIN_BLOCO;
    /* Formato 4: os 8 bytes aleatorios sao NOVOS: o bloco de saida nao herda
     * os do bloco de entrada. Sem isso, traduzir o mesmo bloco duas vezes
     * para a mesma chave daria o mesmo resultado, e o host saberia que dois
     * blocos de origens diferentes levam o mesmo campo.
     *
     * O formato 0 nao tem aleatorio: mesmo PIN, mesmo PAN e mesma chave dao
     * sempre o mesmo bloco. E do formato, e nao ha o que fazer aqui. */
    if (drbg_dispositivo_bytes(&g_pin[PIN_BLOCO / 2u], PIN_BLOCO / 2u) != 0) {
        r = -3;
    } else if ((pin_fecha_uma(i, formato, pan_campo, bloco) != 0) ||
               (pin_fecha_uma(i, formato, pan_campo, segunda) != 0)) {
        r = -3;
    } else {
        for (j = 0u; j < tam; j++) {
            dif |= (uint8_t)(bloco[j] ^ segunda[j]);
        }
        if (dif != 0u) {
            erro_grave_marca();
            r = -2;
        } else {
            g_slots[i].contador_uso++;
            r = 0;
        }
    }
    wipe(segunda, sizeof segunda);
    if (r != 0) {
        wipe(bloco, tam);
    }
    keystore_pin_apaga();
    (void)hsm_cfs_wipe();
    return r;
}

/* ------------------------------------------------------------------
 * DUKPT TDES (etapa 8.8a) e DUKPT AES (etapa 8.8b)
 *
 * A BDK e uma chave de slot como as outras (uso B0, modo 'X'; 3DES duplo,
 * AES-128 ou AES-256),
 * e chega ao slot efemero pelo key block do host. O que se deriva dela -- a
 * IPEK de um terminal, a chave de PIN de uma transacao -- nunca entra em
 * slot nenhum: existe em variavel local, durante a conta, e sai apagado.
 * ------------------------------------------------------------------ */

/* A BDK do slot: DUKPT_TDES se for uma BDK TDES que pode derivar (3DES
 * duplo), DUKPT_AES se for uma BDK AES (AES-128 ou AES-256, etapa 8.8b), 0
 * se nao for BDK. So o modo 'X': uma BDK nao cifra nem faz MAC, e uma chave
 * de outro uso nao deriva. */
#define DUKPT_TDES  1
#define DUKPT_AES   2
static int bdk_tipo(int i)
{
    if ((g_slots[i].uso[0] != (uint8_t)KS_USO_BDK[0]) ||
        (g_slots[i].uso[1] != (uint8_t)KS_USO_BDK[1]) ||
        (g_slots[i].modo != KS_MODO_DERIVA)) {
        return 0;
    }
    if ((g_slots[i].algoritmo == KS_ALG_TDES) &&
        (g_slots[i].key_len == DUKPT_TDES_CHAVE)) {
        return DUKPT_TDES;
    }
    if ((g_slots[i].algoritmo == KS_ALG_AES) &&
        ((g_slots[i].key_len == DUKPT_AES128) ||
         (g_slots[i].key_len == DUKPT_AES256))) {
        return DUKPT_AES;
    }
    return 0;
}

/* Abre um PIN block formato 4 sob uma chave AES de `n` bytes que nao mora
 * em slot (a chave de PIN de uma transacao DUKPT AES):
 *
 *     campo do PIN = D( D(bloco) ^ campo do PAN )
 *
 * AES-256 pelo coprocessador, AES-128 pelo motor em C. Nao reaproveita
 * pin_passada4(), que le a chave do slot e foi validada assim.
 * FRONTEIRA: dentro. `meio` sai apagado. */
static int pin_abre4_chave(const uint8_t *chave, uint32_t n,
                           const uint8_t pan[PIN_BLOCO],
                           const uint8_t bloco[PIN_BLOCO],
                           uint8_t campo[PIN_BLOCO])
{
    aes128_ctx_t *ctx = aes128_ctx_comum();
    uint8_t       meio[PIN_BLOCO];
    uint32_t      j;
    int           r = -1;

    if (n == DUKPT_AES128) {
        if (aes128_prepara(ctx, chave) == 0) {
            aes128_bloco(ctx, bloco, meio, 0);
            for (j = 0u; j < PIN_BLOCO; j++) {
                meio[j] ^= pan[j];
            }
            aes128_bloco(ctx, meio, campo, 0);
            r = 0;
        }
        aes128_apaga(ctx);
    } else if (n == DUKPT_AES256) {
        if ((hsm_cfs_aes_key(chave) == 0) &&
            (hsm_cfs_aes_block(bloco, meio, 0) == 0)) {
            for (j = 0u; j < PIN_BLOCO; j++) {
                meio[j] ^= pan[j];
            }
            if (hsm_cfs_aes_block(meio, campo, 0) == 0) {
                r = 0;
            }
        }
        (void)hsm_cfs_wipe();
    }
    wipe(meio, sizeof meio);
    if (r != 0) {
        wipe(campo, PIN_BLOCO);
    }
    return r;
}

/* Deriva a chave de PIN da transacao e abre o bloco uma vez.
 * TDES: formato 0, a chave 3DES dupla. AES: formato 4, a chave de trabalho
 * de `n_trab` bytes. FRONTEIRA: dentro. A chave sai apagada. */
static int dukpt_abre_uma(int i, int tipo, const uint8_t *ksn,
                          uint32_t n_trab, const uint8_t *pan_campo,
                          const uint8_t *bloco, uint8_t campo4[PIN_BLOCO],
                          int *valido)
{
    uint8_t chave[DUKPT_AES256], campo0[PIN_BLOCO_0];
    int     r = -3;

    *valido = 0;
    if (tipo == DUKPT_TDES) {
        if ((dukpt_tdes_chave_pin(g_slots[i].chave, ksn, chave) == 0) &&
            (pin_passada0_chave(chave, DUKPT_TDES_CHAVE, pan_campo, bloco,
                                campo0, 0) == 0)) {
            *valido = pinblock_f0_para_f4(campo0, campo4);
            r = 0;
        }
    } else {
        if ((dukpt_aes_chave_pin(g_slots[i].chave, g_slots[i].key_len, ksn,
                                 n_trab, chave) == 0) &&
            (pin_abre4_chave(chave, n_trab, pan_campo, bloco, campo4) == 0)) {
            *valido = pinblock_campo_valido(campo4);
            r = 0;
        }
    }
    wipe(chave, sizeof chave);
    wipe(campo0, sizeof campo0);
    return r;
}

/* FRONTEIRA: dentro. Como keystore_pin_abre(): o campo do PIN fica em g_pin,
 * e a conta e feita duas vezes. */
int keystore_dukpt_pin_abre(ks_handle_t h, const uint8_t *ksn, uint32_t ksn_n,
                            uint8_t formato, uint32_t n_trab,
                            const uint8_t *pan_campo, const uint8_t *bloco)
{
    int      i = indice(h);
    uint8_t  a[PIN_BLOCO], b[PIN_BLOCO];
    uint32_t j;
    uint8_t  dif = 0u;
    int      va = 0, vb = 0;
    int      tipo, r;

    keystore_pin_apaga();
    if ((i < 0) || (ksn == 0) || (pan_campo == 0) || (bloco == 0)) {
        return -3;
    }
    /* O DUKPT TDES leva o PIN block formato 0, cifrado em 3DES; o DUKPT AES,
     * o formato 4, cifrado em AES-128 ou AES-256. */
    tipo = bdk_tipo(i);
    if (tipo == DUKPT_TDES) {
        if ((formato != (uint8_t)PIN_FORMATO_0) || (ksn_n != DUKPT_KSN_LEN)) {
            return -1;
        }
        if (!dukpt_ksn_valido(ksn)) {
            return -5;
        }
    } else if (tipo == DUKPT_AES) {
        if ((formato != (uint8_t)PIN_FORMATO_4) ||
            (ksn_n != DUKPT_AES_KSN_LEN) ||
            ((n_trab != DUKPT_AES128) && (n_trab != DUKPT_AES256))) {
            return -1;
        }
        if (!dukpt_aes_ksn_valido(ksn)) {
            return -5;
        }
    } else {
        return -1;
    }
    if ((dukpt_abre_uma(i, tipo, ksn, n_trab, pan_campo, bloco, a, &va) != 0) ||
        (dukpt_abre_uma(i, tipo, ksn, n_trab, pan_campo, bloco, b, &vb) != 0)) {
        r = -3;
    } else {
        for (j = 0u; j < PIN_BLOCO; j++) {
            dif |= (uint8_t)(a[j] ^ b[j]);
        }
        if ((dif != 0u) || (va != vb)) {
            erro_grave_marca();
            r = -2;
        } else if (!va) {
            r = -4;
        } else {
            for (j = 0u; j < PIN_BLOCO; j++) {
                g_pin[j] = a[j];
            }
            g_pin_ok = 1u;
            g_slots[i].contador_uso++;
            r = 0;
        }
    }
    wipe(a, sizeof a);
    wipe(b, sizeof b);
    return r;
}

/* A chave inicial do terminal: a IPEK (TDES) ou a IK (AES, do tamanho da
 * BDK). Devolve o tamanho, ou 0 em erro. FRONTEIRA: dentro. */
static uint32_t dukpt_inicial(int i, int tipo, const uint8_t *ksn,
                              uint8_t chave[DUKPT_AES256])
{
    if (tipo == DUKPT_TDES) {
        return (dukpt_tdes_ipek(g_slots[i].chave, ksn, chave) == 0)
               ? DUKPT_TDES_CHAVE : 0u;
    }
    return (dukpt_aes_ik(g_slots[i].chave, g_slots[i].key_len, ksn, chave) == 0)
           ? g_slots[i].key_len : 0u;
}

/* FRONTEIRA: dentro ate a ultima linha. O que sai em `saida` e criptograma,
 * e o KCV. A chave inicial e derivada duas vezes e comparada antes de ser
 * embrulhada: uma chave errada, injetada num terminal, so apareceria na
 * primeira transacao dele, em campo. */
int keystore_dukpt_ipek(ks_handle_t h, const uint8_t *ksn, uint32_t ksn_n,
                        const uint8_t kbek[KS_KEY_MAX],
                        const uint8_t kbak[KS_KEY_MAX], uint8_t n,
                        char *saida, uint32_t *saida_n,
                        uint8_t kcv[KS_KCV_LEN])
{
    int        i = indice(h);
    uint8_t    ipek[DUKPT_AES256], outra[DUKPT_AES256];
    uint8_t    ench[TR31_BLOCO];
    tr31_cab_t cab;
    uint32_t   j, len = 0u, len2;
    uint8_t    dif = 0u, alg;
    int        tipo, r = -1;

    if ((i < 0) || (ksn == 0) || (kbek == 0) || (kbak == 0) ||
        (saida == 0) || (saida_n == 0) || (kcv == 0)) {
        return -1;
    }
    tipo = bdk_tipo(i);
    if ((tipo == 0) ||
        (ksn_n != ((tipo == DUKPT_TDES) ? DUKPT_KSN_LEN : DUKPT_AES_KSN_LEN))) {
        return -4;
    }
    /* A regra de forca do K4 vale aqui: a IPEK e 3DES dupla, e qualquer KEK
     * deste equipamento a leva; a IK AES so sai sob KEK AES. */
    alg = (tipo == DUKPT_TDES) ? KS_ALG_TDES : KS_ALG_AES;
    if (!keystore_kek_transporta(n, alg, (tipo == DUKPT_TDES)
                                         ? (uint8_t)DUKPT_TDES_CHAVE
                                         : g_slots[i].key_len)) {
        return -3;
    }
    len  = dukpt_inicial(i, tipo, ksn, ipek);
    len2 = dukpt_inicial(i, tipo, ksn, outra);
    if ((len == 0u) || (len2 != len)) {
        len = 0u;
        goto fim;
    }
    for (j = 0u; j < len; j++) {
        dif |= (uint8_t)(ipek[j] ^ outra[j]);
    }
    if (dif != 0u) {
        erro_grave_marca();
        r = -2;
        goto fim;
    }
    /* Cabecalho da chave inicial: uso B1 (chave inicial de DUKPT), o
     * algoritmo da BDK, modo 'X' (ela deriva as chaves do terminal) e
     * exportabilidade 'N': o destino e o terminal, e de la ela nao sai mais. */
    cab.uso[0]          = (uint8_t)'B';
    cab.uso[1]          = (uint8_t)'1';
    cab.algoritmo       = alg;
    cab.modo            = KS_MODO_DERIVA;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = KS_EXP_NAO;
    if (tipo == DUKPT_TDES) {
        r = kcv_tdes(ipek, DUKPT_TDES_CHAVE, kcv);
    } else if (len == DUKPT_AES128) {
        r = kcv_aes128(ipek, kcv);
    } else {
        r = keystore_kcv(ipek, (uint8_t)len, kcv);
    }
    if ((r != 0) || (drbg_dispositivo_bytes(ench, sizeof ench) != 0)) {
        r = -1;
        goto fim;
    }
    if (n == KS_KEY_MAX) {
        r = tr31_embrulha(kbek, kbak, &cab, ipek, (uint8_t)len, ench,
                          (uint8_t)TR31_BLOCO, saida, saida_n);
    } else {
        r = tr31b_embrulha(kbek, kbak, n, &cab, ipek, (uint8_t)len, ench,
                           (uint8_t)TR31B_BLOCO, saida, saida_n);
    }
    if (r == 0) {
        g_slots[i].contador_uso++;
    } else {
        r = -1;
    }
fim:
    wipe(ipek, sizeof ipek);
    wipe(outra, sizeof outra);
    wipe(ench, sizeof ench);
    if (r != 0) {
        wipe(kcv, KS_KCV_LEN);
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* Verificacao de PIN: offset e PVV (fase 8, etapa 8.5)                */
/* ------------------------------------------------------------------ */

static int tabela_confere(const uint8_t tab[PINV_TABELA],
                          const uint8_t kcv[KS_KCV_LEN],
                          const uint8_t mac[KS_TABELA_MAC]);

/* 1 se o slot e chave de verificacao de PIN do metodo `metodo` ('1' offset,
 * '2' PVV), 3DES, e o `modo` permite `precisa` (GERA/VERIFICA; 'C' permite
 * as duas). O codigo exato do uso: uma chave do offset que calculasse PVV
 * seria a mesma chave em dois metodos, e o que um revela ajudaria o outro. */
static int pvk_pode(int i, uint8_t metodo, uint8_t precisa)
{
    if ((g_slots[i].algoritmo != (uint8_t)KS_ALG_TDES) ||
        (g_slots[i].uso[0] != (uint8_t)KS_USO_PVK_OFFSET[0]) ||
        (g_slots[i].uso[1] != metodo)) {
        return 0;
    }
    return modo_mac_ok(g_slots[i].modo, precisa);
}

/* Um bloco de 3DES sob a chave do slot. As subchaves sao derivadas AQUI, a
 * cada chamada, e apagadas na saida. FRONTEIRA: dentro. */
static int pvk_cifra(int i, const uint8_t entrada[DES_BLOCO],
                     uint8_t saida[DES_BLOCO])
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    int         r = -1;

    if (tdes_prepara(ctx, g_slots[i].chave, g_slots[i].key_len) == 0) {
        tdes_bloco(ctx, entrada, saida, 1);
        r = 0;
    }
    tdes_apaga(ctx);
    return r;
}

/* Os digitos do PIN aberto, em valores, e o tamanho. g_pin tem a forma do
 * campo do formato 4: controle, tamanho, e os digitos a partir do terceiro
 * meio-byte. As 12 posicoes sao copiadas sempre; as que passam do tamanho
 * levam enchimento, e ninguem as usa. FRONTEIRA: dentro. */
static uint32_t pin_digitos(uint8_t pin[PIN_MAX])
{
    uint32_t k;

    for (k = 0u; k < PIN_MAX; k++) {
        uint8_t b = g_pin[(2u + k) >> 1];
        pin[k] = (uint8_t)((((2u + k) & 1u) == 0u) ? (b >> 4) : (b & 0x0Fu));
    }
    return (uint32_t)(g_pin[0] & 0x0Fu);
}

/* FRONTEIRA: dentro. O PIN natural e tao bom quanto o PIN, porque o offset e
 * publico: as copias saem apagadas em todo caminho.
 *
 * A tabela e conferida AQUI, contra o KCV da chave que esta no slot, e nao
 * contra um KCV que o host informe: so assim ela vale para a chave para a
 * qual foi autorizada. O veredito final e calculado duas vezes, cada um a
 * partir de uma das duas cifras: uma falha na comparacao nao vira 00. */
int keystore_pin_offset(ks_handle_t h, int gerar,
                        const uint8_t tab[PINV_TABELA],
                        const uint8_t mac[KS_TABELA_MAC],
                        const uint8_t dados[PINV_DADOS],
                        uint8_t *offset, uint32_t *offset_n)
{
    int      i = indice(h);
    uint8_t  ca[DES_BLOCO], cb[DES_BLOCO];
    uint8_t  na[PINV_NATURAL], nb[PINV_NATURAL];
    uint8_t  pin[PIN_MAX], off[PIN_MAX];
    uint32_t n, j;
    uint8_t  dif = 0u;
    int      r, va, vb;

    if ((i < 0) || (tab == 0) || (mac == 0) || (dados == 0) ||
        (offset == 0) || (offset_n == 0) || (g_pin_ok == 0u)) {
        keystore_pin_apaga();
        return -3;
    }
    if (!pvk_pode(i, (uint8_t)KS_USO_PVK_OFFSET[1],
                  gerar ? KS_MODO_GERA : KS_MODO_VERIFICA)) {
        keystore_pin_apaga();
        return -1;
    }
    r = tabela_confere(tab, g_slots[i].kcv, mac);
    if (r != 1) {
        keystore_pin_apaga();
        return (r == 0) ? -5 : r;
    }
    n = pin_digitos(pin);
    if ((pvk_cifra(i, dados, ca) != 0) || (pvk_cifra(i, dados, cb) != 0)) {
        r = -3;
    } else {
        for (j = 0u; j < DES_BLOCO; j++) {
            dif |= (uint8_t)(ca[j] ^ cb[j]);
        }
        if (dif != 0u) {
            erro_grave_marca();
            r = -2;
        } else {
            pinv_decimaliza(ca, tab, na);
            pinv_decimaliza(cb, tab, nb);
            g_slots[i].contador_uso++;
            if (gerar) {
                /* O offset sai das duas contas, e sai so se concordam. */
                pinv_offset(pin, na, n, off);
                pinv_offset(pin, nb, n, offset);
                dif = 0u;
                for (j = 0u; j < n; j++) {
                    dif |= (uint8_t)(off[j] ^ offset[j]);
                    offset[j] = (uint8_t)(off[j] + (uint8_t)'0');
                }
                if (dif != 0u) {
                    erro_grave_marca();
                    wipe(offset, n);
                    r = -2;
                } else {
                    *offset_n = n;
                    r = 0;
                }
            } else if (*offset_n != n) {
                /* Tamanho diferente: nao confere. O mesmo codigo do PIN
                 * errado, para o host nao separar um caso do outro. */
                r = 1;
            } else {
                for (j = 0u; j < n; j++) {
                    off[j] = (uint8_t)(offset[j] - (uint8_t)'0');
                }
                va = pinv_offset_confere(pin, na, off, n);
                vb = pinv_offset_confere(pin, nb, off, n);
                if (va != vb) {
                    erro_grave_marca();
                    r = -2;
                } else {
                    r = va ? 0 : 1;
                }
            }
        }
    }
    wipe(ca, sizeof ca);
    wipe(cb, sizeof cb);
    wipe(na, sizeof na);
    wipe(nb, sizeof nb);
    wipe(pin, sizeof pin);
    wipe(off, sizeof off);
    keystore_pin_apaga();
    return r;
}

/* FRONTEIRA: dentro. O TSP leva quatro digitos do PIN; o resultado da cifra
 * e segredo ate virar PVV. */
int keystore_pin_pvv(ks_handle_t h, int gerar, const uint8_t *pan,
                     uint32_t pan_n, uint8_t indice_pvk,
                     uint8_t pvv[PINV_PVV])
{
    int      i = indice(h);
    uint8_t  tsp[PINV_DADOS], ca[DES_BLOCO], cb[DES_BLOCO];
    uint8_t  pin[PIN_MAX], calc[PINV_PVV], calc2[PINV_PVV];
    uint32_t j;
    uint8_t  dif = 0u;
    int      r, va, vb;

    if ((i < 0) || (pan == 0) || (pvv == 0) || (g_pin_ok == 0u)) {
        keystore_pin_apaga();
        return -3;
    }
    if (!pvk_pode(i, (uint8_t)KS_USO_PVK_PVV[1],
                  gerar ? KS_MODO_GERA : KS_MODO_VERIFICA)) {
        keystore_pin_apaga();
        return -1;
    }
    (void)pin_digitos(pin);
    if (pinv_pvv_tsp(pan, pan_n, indice_pvk, pin, tsp) != 0) {
        r = -3;
    } else if ((pvk_cifra(i, tsp, ca) != 0) || (pvk_cifra(i, tsp, cb) != 0)) {
        r = -3;
    } else {
        for (j = 0u; j < DES_BLOCO; j++) {
            dif |= (uint8_t)(ca[j] ^ cb[j]);
        }
        if (dif != 0u) {
            erro_grave_marca();
            r = -2;
        } else {
            /* Uma extracao de cada cifra: a comparacao final tambem e
             * feita duas vezes. */
            pinv_pvv_extrai(ca, calc);
            pinv_pvv_extrai(cb, calc2);
            g_slots[i].contador_uso++;
            if (gerar) {
                dif = 0u;
                for (j = 0u; j < PINV_PVV; j++) {
                    dif |= (uint8_t)(calc[j] ^ calc2[j]);
                    pvv[j] = (uint8_t)(calc[j] + (uint8_t)'0');
                }
                if (dif != 0u) {
                    erro_grave_marca();
                    wipe(pvv, PINV_PVV);
                    r = -2;
                } else {
                    r = 0;
                }
            } else {
                uint8_t da = 0u, db = 0u;
                for (j = 0u; j < PINV_PVV; j++) {
                    da |= (uint8_t)(calc[j]  ^ (uint8_t)(pvv[j] - (uint8_t)'0'));
                    db |= (uint8_t)(calc2[j] ^ (uint8_t)(pvv[j] - (uint8_t)'0'));
                }
                va = (da == 0u) ? 1 : 0;
                vb = (db == 0u) ? 1 : 0;
                if (va != vb) {
                    erro_grave_marca();
                    r = -2;
                } else {
                    r = va ? 0 : 1;
                }
            }
        }
    }
    wipe(tsp, sizeof tsp);
    wipe(ca, sizeof ca);
    wipe(cb, sizeof cb);
    wipe(pin, sizeof pin);
    wipe(calc, sizeof calc);
    wipe(calc2, sizeof calc2);
    keystore_pin_apaga();
    return r;
}

/* ------------------------------------------------------------------ */
/* CVV, CVV2 e iCVV (fase 8, etapa 8.6)                                */
/* ------------------------------------------------------------------ */

/* 1 se o slot e chave de verificacao de cartao: uso C0, 3DES de comprimento
 * duplo, e o `modo` permite `precisa`. O metodo usa a metade esquerda da
 * chave sozinha, e o par A/B do mercado e uma chave dupla: chave tripla nao
 * tem lugar nele. */
static int cvk_pode(int i, uint8_t precisa)
{
    if ((g_slots[i].algoritmo != (uint8_t)KS_ALG_TDES) ||
        (g_slots[i].key_len != (uint8_t)TDES_CHAVE_2) ||
        (g_slots[i].uso[0] != (uint8_t)KS_USO_CVK[0]) ||
        (g_slots[i].uso[1] != (uint8_t)KS_USO_CVK[1])) {
        return 0;
    }
    return modo_mac_ok(g_slots[i].modo, precisa);
}

/* Uma conta do CVV: X = DES_A(D1) xor D2, C = 3DES_AB(X). O DES de A sai do
 * motor de 3DES com a chave A.A (K1 = K2: o meio desfaz o primeiro passo),
 * porque ha um contexto so no firmware. As subchaves e os intermediarios sao
 * apagados na saida. FRONTEIRA: dentro. */
static int cvk_cifra(int i, const uint8_t dados[CVV_DADOS],
                     uint8_t saida[DES_BLOCO])
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t     aa[TDES_CHAVE_2], x[DES_BLOCO];
    uint32_t    j;
    int         r = -1;

    for (j = 0u; j < DES_CHAVE; j++) {
        aa[j]             = g_slots[i].chave[j];
        aa[DES_CHAVE + j] = g_slots[i].chave[j];
    }
    if (tdes_prepara(ctx, aa, TDES_CHAVE_2) == 0) {
        tdes_bloco(ctx, dados, x, 1);
        for (j = 0u; j < DES_BLOCO; j++) {
            x[j] ^= dados[DES_BLOCO + j];
        }
        if (tdes_prepara(ctx, g_slots[i].chave, TDES_CHAVE_2) == 0) {
            tdes_bloco(ctx, x, saida, 1);
            r = 0;
        }
    }
    tdes_apaga(ctx);
    wipe(aa, sizeof aa);
    wipe(x, sizeof x);
    return r;
}

/* FRONTEIRA: dentro. O resultado da cifra e segredo ate virar CVV, e o CVV
 * calculado na verificacao nao sai: so o veredito. */
int keystore_cvv(ks_handle_t h, int gerar, const uint8_t dados[CVV_DADOS],
                 uint8_t cvv[CVV_DIGITOS])
{
    int      i = indice(h);
    uint8_t  ca[DES_BLOCO], cb[DES_BLOCO];
    uint8_t  calc[CVV_DIGITOS], calc2[CVV_DIGITOS];
    uint32_t j;
    uint8_t  dif = 0u;
    int      r, va, vb;

    if ((i < 0) || (dados == 0) || (cvv == 0)) {
        return -3;
    }
    if (!cvk_pode(i, gerar ? KS_MODO_GERA : KS_MODO_VERIFICA)) {
        return -1;
    }
    if ((cvk_cifra(i, dados, ca) != 0) || (cvk_cifra(i, dados, cb) != 0)) {
        r = -3;
    } else {
        for (j = 0u; j < DES_BLOCO; j++) {
            dif |= (uint8_t)(ca[j] ^ cb[j]);
        }
        if (dif != 0u) {
            erro_grave_marca();
            r = -2;
        } else {
            /* Uma extracao de cada cifra: a comparacao final tambem e
             * feita duas vezes. */
            cvv_extrai(ca, calc);
            cvv_extrai(cb, calc2);
            g_slots[i].contador_uso++;
            if (gerar) {
                dif = 0u;
                for (j = 0u; j < CVV_DIGITOS; j++) {
                    dif |= (uint8_t)(calc[j] ^ calc2[j]);
                    cvv[j] = (uint8_t)(calc[j] + (uint8_t)'0');
                }
                if (dif != 0u) {
                    erro_grave_marca();
                    wipe(cvv, CVV_DIGITOS);
                    r = -2;
                } else {
                    r = 0;
                }
            } else {
                uint8_t da = 0u, db = 0u;
                for (j = 0u; j < CVV_DIGITOS; j++) {
                    da |= (uint8_t)(calc[j]  ^ (uint8_t)(cvv[j] - (uint8_t)'0'));
                    db |= (uint8_t)(calc2[j] ^ (uint8_t)(cvv[j] - (uint8_t)'0'));
                }
                va = (da == 0u) ? 1 : 0;
                vb = (db == 0u) ? 1 : 0;
                if (va != vb) {
                    erro_grave_marca();
                    r = -2;
                } else {
                    r = va ? 0 : 1;
                }
            }
        }
    }
    wipe(ca, sizeof ca);
    wipe(cb, sizeof cb);
    wipe(calc, sizeof calc);
    wipe(calc2, sizeof calc2);
    return r;
}

int keystore_cmac(ks_handle_t h, const uint8_t *msg, uint32_t msg_n,
                  uint8_t tag[CMAC_TAG_LEN])
{
    int      i = indice(h);
    uint8_t  segunda[CMAC_TAG_LEN];
    uint32_t j;
    uint8_t  dif = 0u;

    if ((i < 0) || (tag == 0)) {
        return -1;
    }
    if (!uso_mac(i) || !modo_mac_ok(g_slots[i].modo, KS_MODO_GERA)) {
        return -1;
    }
    if ((cmac_aes256(g_slots[i].chave, msg, msg_n, tag) != 0) ||
        (cmac_aes256(g_slots[i].chave, msg, msg_n, segunda) != 0)) {
        wipe(tag, CMAC_TAG_LEN);
        wipe(segunda, CMAC_TAG_LEN);
        return -1;
    }
    g_slots[i].contador_uso++;

    /* A chave expandida fica no coprocessador depois do CMAC. Limpar
     * agora, e nao "na proxima vez que alguem carregar chave". */
    (void)hsm_cfs_wipe();

    /* Dupla execucao, fase 6. */
    for (j = 0u; j < CMAC_TAG_LEN; j++) {
        dif |= (uint8_t)(tag[j] ^ segunda[j]);
    }
    wipe(segunda, CMAC_TAG_LEN);
    if (dif != 0u) {
        wipe(tag, CMAC_TAG_LEN);
        erro_grave_marca();
        return -2;
    }
    return 0;
}

int keystore_cmac_verifica(ks_handle_t h, const uint8_t *msg, uint32_t msg_n,
                           const uint8_t tag[CMAC_TAG_LEN])
{
    int i = indice(h);
    int r, r2;

    if ((i < 0) || (tag == 0)) {
        return -1;
    }
    if (!uso_mac(i) || !modo_mac_ok(g_slots[i].modo, KS_MODO_VERIFICA)) {
        return -1;
    }

    /* Tempo constante, e DENTRO da fronteira -- ver keystore.h. */
    r  = cmac_aes256_verifica(g_slots[i].chave, msg, msg_n, tag);
    r2 = cmac_aes256_verifica(g_slots[i].chave, msg, msg_n, tag);
    g_slots[i].contador_uso++;
    (void)hsm_cfs_wipe();

    /* Dupla execucao, fase 6: o veredito e o que uma falha quer inverter. */
    if (r != r2) {
        erro_grave_marca();
        return -2;
    }
    return r;
}

int comp_componente(uint8_t n, uint8_t total, uint8_t algoritmo,
                    const uint8_t *comp, uint8_t comp_n,
                    uint8_t kcv[KS_KCV_LEN])
{
    uint8_t i;
    int     v;

    if ((comp == 0) || (kcv == 0)) {
        return -1;
    }
    if ((total < KS_COMP_MIN) || (total > KS_COMP_MAX)) {
        return -1;
    }
    /* AES-256, AES-128 (so a BDK do DUKPT AES, conferido na instalacao),
     * 3DES duplo ou triplo. */
    if (!(((algoritmo == KS_ALG_AES) &&
           ((comp_n == KS_KEY_MAX) || (comp_n == AES128_CHAVE))) ||
          ((algoritmo == KS_ALG_TDES) &&
           ((comp_n == TDES_CHAVE_2) || (comp_n == TDES_CHAVE_3))))) {
        return -1;
    }

    if (n == 0u) {
        /* Reinicia. E a unica forma de abandonar uma montagem comecada
         * errado sem precisar de um comando de cancelar -- que seria mais
         * um opcode para a mesma coisa. */
        wipe_padrao(g_comp, sizeof g_comp);
        g_comp_n     = 0u;
        g_comp_total = total;
        g_comp_alg   = algoritmo;
        g_comp_len   = comp_n;
    } else {
        /* Fora de ordem, anunciando um total diferente do que comecou, ou
         * com outro algoritmo ou tamanho: recusa SEM tocar no acumulado.
         * Um host que erre a sequencia nao pode destruir a cerimonia de
         * quem esta na frente da placa. */
        if ((n != g_comp_n) || (total != g_comp_total) ||
            (algoritmo != g_comp_alg) || (comp_n != g_comp_len)) {
            return -1;
        }
    }

    /* O KCV do COMPONENTE, calculado antes de acumular -- e o que o
     * custodiante confere. */
    v = (algoritmo == KS_ALG_TDES) ? kcv_tdes(comp, comp_n, kcv)
      : (comp_n == AES128_CHAVE)   ? kcv_aes128(comp, kcv)
                                   : keystore_kcv(comp, KS_KEY_MAX, kcv);
    if (v != 0) {
        return -1;
    }

    for (i = 0u; i < comp_n; i++) {
        g_comp[i] ^= comp[i];
    }
    g_comp_n++;
    return 0;
}

uint8_t comp_carregados(void)
{
    return g_comp_n;
}

uint8_t comp_total(void)
{
    return g_comp_total;
}

ks_handle_t comp_instala(const uint8_t uso[2], uint8_t algoritmo,
                         uint8_t modo, uint8_t exportabilidade)
{
    ks_handle_t h = KS_HANDLE_INVALIDO;

    /* O algoritmo do cabecalho tem de ser o dos componentes: 32 bytes
     * montados como AES nao viram 3DES na instalacao, nem o contrario. */
    if ((g_comp_total >= KS_COMP_MIN) && (g_comp_n == g_comp_total) &&
        (algoritmo == g_comp_alg)) {
        h = keystore_instala(uso, algoritmo, modo, exportabilidade,
                             g_comp, g_comp_len);
    }

    /* Limpa em QUALQUER desfecho, inclusive na falha. Uma chave montada
     * pendurada seria material de chave esperando por um comando que
     * talvez nao venha -- e o operador que errou o cabecalho refaz a
     * cerimonia, que e o comportamento certo para uma chave que ele nao
     * conseguiu instalar. */
    wipe_padrao(g_comp, sizeof g_comp);
    g_comp_n     = 0u;
    g_comp_total = 0u;
    g_comp_alg   = 0u;
    g_comp_len   = 0u;
    return h;
}

/* O ponto único onde `exportabilidade` decide. Os dois caminhos de
 * saída -- keystore_exporta() (bytes, para o key block do console) e
 * keystore_embrulha_kek() (já embrulhada, porta host) -- passam por aqui.
 * 'E' e 'S' saem; ver keystore.h sobre por que 'S' não é mais estrito. */
static int exportavel(int i)
{
    return g_slots[i].exportabilidade != KS_EXP_NAO;
}

/* Embrulha o slot `i` sob KBEK/KBAK, com o cabeçalho do próprio slot.
 *
 * FRONTEIRA: dentro. Os bytes da chave vão do slot direto para o
 * tr31_embrulha(); o enchimento é aleatório por norma e sai zerado. Quem
 * decide SE pode embrulhar é o chamador -- esta função só sabe COMO. */
static int embrulha_slot(int i, const uint8_t kbek[KS_KEY_MAX],
                         const uint8_t kbak[KS_KEY_MAX],
                         char *saida, uint32_t *saida_n)
{
    uint8_t    enchimento[TR31_BLOCO];
    tr31_cab_t cab;
    int        r = -1;

    if (drbg_dispositivo_bytes(enchimento, sizeof enchimento) != 0) {
        goto fim;
    }
    cab.uso[0]          = g_slots[i].uso[0];
    cab.uso[1]          = g_slots[i].uso[1];
    cab.algoritmo       = g_slots[i].algoritmo;
    cab.modo            = g_slots[i].modo;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = g_slots[i].exportabilidade;
    r = tr31_embrulha(kbek, kbak, &cab, g_slots[i].chave,
                      g_slots[i].key_len, enchimento,
                      (uint8_t)sizeof enchimento, saida, saida_n);
fim:
    wipe(enchimento, sizeof enchimento);
    return r;
}

uint8_t keystore_exporta(ks_handle_t h, uint8_t out[KS_KEY_MAX])
{
    int     i = indice(h);
    uint8_t k;

    /* O slot efêmero nunca exporta: a chave dele chegou num key block, e
     * quem o mandou já tem o bloco. */
    if ((i < 0) || (i == EFEMERA) || (out == 0)) {
        return 0u;
    }

    if (!exportavel(i)) {
        return 0u;
    }

    for (k = 0u; k < g_slots[i].key_len; k++) {
        out[k] = g_slots[i].chave[k];
    }
    return g_slots[i].key_len;
}

/* ------------------------------------------------------------------
 * LMK
 * ------------------------------------------------------------------ */

void lmk_zeroiza(void)
{
    /* Apagar a LMK apaga TUDO, e por isso esta funcao e um apelido de
     * `keystore_init()` e nao uma segunda implementacao.
     *
     * As chaves derivadas não sobrevivem à chave que as protege: zeroizar
     * a LMK e deixar os slots guardaria chave que ninguém mais consegue
     * exportar nem reimportar -- e que continua utilizável, que é pior.
     *
     * Duas implementações de zeroização divergiriam no dia em que alguém
     * acrescentasse um campo, e a que ficasse para trás deixaria material
     * vivo sem que nenhum teste notasse. */
    keystore_init();
}

int lmk_componente(uint8_t n, const uint8_t comp[KS_KEY_MAX])
{
    uint8_t i, acc;

    if ((comp == 0) || (n != g_lmk_comps) || (n >= LMK_N_COMPONENTES)) {
        return -1;                       /* fora de ordem, ou já completa */
    }

    /* XOR: nenhum componente isolado revela nada sobre a LMK, e a ordem não
     * importa para o resultado -- mas é exigida aqui para que o firmware
     * saiba quantos entraram sem depender do host dizer. */
    for (i = 0u; i < KS_KEY_MAX; i++) {
        g_lmk[i] ^= comp[i];
    }
    g_lmk_comps++;

    if (g_lmk_comps == LMK_N_COMPONENTES) {
        /* LMK zerada: recusada, e a cerimonia recomeca. Acontece quando o
         * ultimo componente e o XOR dos anteriores -- cada um parece
         * aleatorio, e a soma e zero. Nao ha como saber qual componente
         * estava errado, entao nao ha o que aproveitar do acumulado.
         *
         * Varredura sem saida antecipada: o tempo nao diz onde parou.
         * LMK "fraca" (de baixa entropia) NAO e checada -- decisao de
         * 2026-10-18: a qualidade do componente e responsabilidade do
         * custodiante, como num HSM comercial. */
        acc = 0u;
        for (i = 0u; i < KS_KEY_MAX; i++) {
            acc |= g_lmk[i];
        }
        if (acc == 0u) {
            lmk_zeroiza();
            return -2;
        }
        if (keystore_kcv(g_lmk, KS_KEY_MAX, g_lmk_kcv) != 0) {
            lmk_zeroiza();
            return -1;
        }
    }
    return 0;
}

uint8_t lmk_componentes_carregados(void)
{
    return g_lmk_comps;
}

int lmk_completa(void)
{
    return (g_lmk_comps == LMK_N_COMPONENTES) ? 1 : 0;
}

int lmk_kcv(uint8_t out[KS_KCV_LEN])
{
    uint8_t i;

    if (!lmk_completa()) {
        wipe(out, KS_KCV_LEN);
        return -1;
    }
    for (i = 0u; i < KS_KCV_LEN; i++) {
        out[i] = g_lmk_kcv[i];
    }
    return 0;
}

int lmk_usa_aes(void)
{
    if (!lmk_completa()) {
        return -1;
    }
    return hsm_cfs_aes_key(g_lmk);
}

/* Única função deste arquivo que passa `g_lmk` para fora do arquivo -- e
 * ela passa para uma derivação, não para um chamador. Ver keystore.h. */
int lmk_deriva_kb(uint8_t kbek[KS_KEY_MAX], uint8_t kbak[KS_KEY_MAX])
{
    if (!lmk_completa()) {
        return -1;
    }
    return tr31_deriva(g_lmk, kbek, kbak);
}

/* ------------------------------------------------------------------
 * Tabela de decimalizacao autorizada (fase 8, etapa 8.5)
 * ------------------------------------------------------------------ */

/* O MAC de uma tabela, amarrado a UMA chave de verificacao, sob uma chave
 * derivada da LMK so para isto:
 *
 *   K   = bloco 1 . bloco 2,  bloco i = CMAC_LMK( [i] . rotulo . 00 . 0100 )
 *   MAC = 8 primeiros bytes de CMAC_K( tabela(16) . KCV da chave V1 (3) )
 *
 * E a SP 800-108 em modo contador, com o CMAC como funcao pseudoaleatoria,
 * que e tambem o que o key block faz para derivar KBEK e KBAK. O rotulo
 * separa esta chave das do key block: um MAC de tabela nao serve de MAC de
 * key block, nem o contrario.
 *
 * O KCV entra para a tabela valer so com a chave para a qual foi autorizada
 * (revisao de 2026-11-15). Sem ele, duas tabelas autorizadas sob a mesma LMK
 * -- uma troca de tabela, ou uma tabela digitada errado e depois corrigida --
 * dariam ao host a variante 3 do ataque: a tabela legitima com uma entrada
 * alterada. Revogar uma tabela passa a ser trocar a chave de verificacao.
 *
 * FRONTEIRA: dentro. A segunda funcao deste arquivo que usa g_lmk fora da
 * cerimonia, e ela tambem a entrega a uma derivacao, nao a um chamador. */
static int tabela_mac(const uint8_t tab[PINV_TABELA],
                      const uint8_t kcv[KS_KCV_LEN],
                      uint8_t mac[KS_TABELA_MAC])
{
    static const uint8_t rotulo[13] = {
        'H', 'S', 'M', '-', 'A', '7', ' ', 'D', 'E', 'C', 'T', 'A', 'B'
    };
    uint8_t  msg[1u + sizeof rotulo + 3u];
    uint8_t  dado[PINV_TABELA + KS_KCV_LEN];
    uint8_t  k[KS_KEY_MAX], tag[CMAC_TAG_LEN];
    uint32_t j;
    int      r = -1;

    if (!lmk_completa()) {
        return -1;
    }
    for (j = 0u; j < sizeof rotulo; j++) {
        msg[1u + j] = rotulo[j];
    }
    msg[1u + sizeof rotulo]      = 0x00u;
    msg[1u + sizeof rotulo + 1u] = 0x01u;      /* 256 bits */
    msg[1u + sizeof rotulo + 2u] = 0x00u;
    for (j = 0u; j < PINV_TABELA; j++) {
        dado[j] = tab[j];
    }
    for (j = 0u; j < KS_KCV_LEN; j++) {
        dado[PINV_TABELA + j] = kcv[j];
    }
    msg[0] = 1u;
    if (cmac_aes256(g_lmk, msg, sizeof msg, &k[0]) == 0) {
        msg[0] = 2u;
        if ((cmac_aes256(g_lmk, msg, sizeof msg, &k[CMAC_TAG_LEN]) == 0) &&
            (cmac_aes256(k, dado, sizeof dado, tag) == 0)) {
            for (j = 0u; j < KS_TABELA_MAC; j++) {
                mac[j] = tag[j];
            }
            r = 0;
        }
    }
    wipe(k, sizeof k);
    wipe(tag, sizeof tag);
    (void)hsm_cfs_wipe();
    return r;
}

int keystore_tabela_autoriza(const uint8_t tab[PINV_TABELA],
                             const uint8_t kcv[KS_KCV_LEN],
                             uint8_t mac[KS_TABELA_MAC])
{
    uint8_t  segunda[KS_TABELA_MAC];
    uint32_t j;
    uint8_t  dif = 0u;
    int      r = -1;

    if ((tab == 0) || (kcv == 0) || (mac == 0) || !pinv_tabela_forma(tab)) {
        return -1;
    }
    if ((tabela_mac(tab, kcv, mac) == 0) &&
        (tabela_mac(tab, kcv, segunda) == 0)) {
        for (j = 0u; j < KS_TABELA_MAC; j++) {
            dif |= (uint8_t)(mac[j] ^ segunda[j]);
        }
        if (dif != 0u) {
            erro_grave_marca();
            r = -2;
        } else {
            r = 0;
        }
    }
    if (r != 0) {
        wipe(mac, KS_TABELA_MAC);
    }
    return r;
}

/* Uma conferencia do MAC da tabela: 1 confere, 0 nao, -1 erro interno. */
static int tabela_confere_uma(const uint8_t tab[PINV_TABELA],
                              const uint8_t kcv[KS_KCV_LEN],
                              const uint8_t mac[KS_TABELA_MAC])
{
    uint8_t  calc[KS_TABELA_MAC];
    uint32_t j;
    uint8_t  dif = 0u;

    if (tabela_mac(tab, kcv, calc) != 0) {
        return -1;
    }
    for (j = 0u; j < KS_TABELA_MAC; j++) {
        dif |= (uint8_t)(calc[j] ^ mac[j]);
    }
    wipe(calc, sizeof calc);
    return (dif == 0u) ? 1 : 0;
}

/* O veredito sobre a tabela e o que uma falha quer inverter: ele e a defesa
 * inteira contra o ataque de decimalizacao. Calculado duas vezes, com a chave
 * do MAC derivada de novo, como o veredito do M2 (fase 6).
 *
 * Devolve 1 confere, 0 nao confere, -2 se as duas discordaram (erro grave
 * marcado), -3 em erro interno. */
static int tabela_confere(const uint8_t tab[PINV_TABELA],
                          const uint8_t kcv[KS_KCV_LEN],
                          const uint8_t mac[KS_TABELA_MAC])
{
    int a, b;

    if (!pinv_tabela_forma(tab)) {
        return 0;
    }
    a = tabela_confere_uma(tab, kcv, mac);
    b = tabela_confere_uma(tab, kcv, mac);
    if ((a < 0) || (b < 0)) {
        return -3;
    }
    if (a != b) {
        erro_grave_marca();
        return -2;
    }
    return a;
}

/* ------------------------------------------------------------------
 * Chave RSA do comando ASCII (fase 7)
 * ------------------------------------------------------------------ */

void keystore_rsa_apaga(void)
{
    wipe_padrao(g_rsa, sizeof g_rsa);
    wipe_padrao(g_der, sizeof g_der);
    g_rsa_ok = 0u;
}

/* Abre na area da chave assimetrica um key block do algoritmo `alg`. */
static int assim_abre(const char *bloco, uint32_t bloco_n, uint8_t alg)
{
    uint8_t    kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    tr31_cab_t cab;
    uint16_t   n = 0u;
    int        r = -1;

    keystore_rsa_apaga();
    if (lmk_deriva_kb(kbek, kbak) != 0) {
        goto fim;
    }
    if (tr31_desembrulha_n(kbek, kbak, bloco, bloco_n, &cab,
                           g_der, (uint16_t)sizeof g_der, &n) != 0) {
        goto fim;
    }
    /* Bloco integro, mas de chave simetrica: e a confusao de tipo, e nao
     * bloco invalido. Vale tambem entre RSA e ECDSA. O tr31.c ja garante
     * que 'R' e 'E' vem com S0 e modo 'S'. */
    if (cab.algoritmo != alg) {
        r = -3;
        goto fim;
    }
    /* O conteudo e PKCS#8. DER que o leitor recusa e bloco invalido: o MAC
     * fechou, mas o que esta dentro nao e uma chave que este equipamento
     * saiba usar. */
    if (alg == (uint8_t)KS_ALG_RSA) {
        if (pkcs8_rsa_le(g_der, n, g_rsa) != 0) {
            goto fim;
        }
    } else {
        int tem_q = 0;
        if (pkcs8_ec_le(g_der, n, g_rsa, &tem_q) != 0) {
            goto fim;
        }
        /* A chave publica e opcional no PKCS#8. Sem ela, Q = d*G. */
        if ((tem_q == 0) && (ec_publica(g_rsa, &g_rsa[EC_BYTES]) != 0)) {
            goto fim;
        }
    }
    wipe_padrao(g_der, sizeof g_der);
    g_rsa_ok = alg;
    r = 0;
fim:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    if (r != 0) {
        keystore_rsa_apaga();
    }
    return r;
}

int keystore_rsa_abre(const char *bloco, uint32_t bloco_n)
{
    return assim_abre(bloco, bloco_n, (uint8_t)KS_ALG_RSA);
}

int keystore_ec_abre(const char *bloco, uint32_t bloco_n)
{
    return assim_abre(bloco, bloco_n, (uint8_t)KS_ALG_EC);
}

int keystore_rsa_gera(uint8_t exportabilidade, char *saida, uint32_t max,
                      uint32_t *saida_n, uint8_t n[256], uint8_t rascunho[256])
{
    uint8_t    kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t    enchimento[TR31_BLOCO];
    tr31_cab_t cab;
    uint32_t   der_n = 0u;
    int        r = -1;

    keystore_rsa_apaga();
    if ((max < TR31_ASCII_GRANDE) ||
        ((exportabilidade != KS_EXP_SIM) && (exportabilidade != KS_EXP_NAO) &&
         (exportabilidade != KS_EXP_SENSIVEL))) {
        return -1;
    }
    if (rsa_gera(g_rsa, n) != 0) {
        goto fim;
    }
    /* Teste de consistencia do par (FIPS 140-3): assinar com a chave nova
     * -- e rsa_crt_assina() ja verifica com e antes de devolver. Um par que
     * nao assina nao sai do dispositivo. O digest e o que houver no
     * rascunho: qualquer valor serve. */
    r = rsa_crt_assina(g_rsa, rascunho, rascunho);
    if (r != 0) {
        if (r == -2) {
            erro_grave_marca();
        }
        goto fim;
    }
    r = -1;

    cab.uso[0]          = (uint8_t)'S';
    cab.uso[1]          = (uint8_t)'0';
    cab.algoritmo       = (uint8_t)KS_ALG_RSA;
    cab.modo            = (uint8_t)KS_MODO_ASSINA;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = exportabilidade;
    if ((lmk_deriva_kb(kbek, kbak) != 0) ||
        (drbg_dispositivo_bytes(enchimento, sizeof enchimento) != 0) ||
        (pkcs8_rsa_monta(g_rsa, n, g_der, (uint32_t)sizeof g_der, &der_n) != 0) ||
        (tr31_embrulha_n(kbek, kbak, &cab, g_der, (uint16_t)der_n,
                         enchimento, (uint8_t)sizeof enchimento,
                         saida, saida_n) != 0)) {
        goto fim;
    }
    r = 0;
fim:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(enchimento, sizeof enchimento);
    keystore_rsa_apaga();
    return r;
}

int keystore_rsa_assina(const uint8_t digest[32], uint8_t sig[256])
{
    int r;

    if (g_rsa_ok != (uint8_t)KS_ALG_RSA) {
        return -1;
    }
    /* -2: a assinatura nao passou na verificacao antes de sair. E a mesma
     * politica da dupla execucao da fase 6 -- nada sai, e o erro grave fica
     * marcado ate o proximo boot. A chave nao e apagada. */
    r = rsa_crt_assina(g_rsa, digest, sig);
    if (r == -2) {
        erro_grave_marca();
    }
    return r;
}

int keystore_ec_assina(const uint8_t digest[32], uint8_t sig[64])
{
    int r;

    if (g_rsa_ok != (uint8_t)KS_ALG_EC) {
        return -1;
    }
    /* -2: mesma politica da assinatura RSA. */
    r = ecdsa_assina(g_rsa, digest, sig);
    if (r == -2) {
        erro_grave_marca();
    }
    return r;
}

int keystore_ec_gera(uint8_t exportabilidade, char *saida, uint32_t max,
                     uint32_t *saida_n, uint8_t q[64])
{
    uint8_t    kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t    enchimento[TR31_BLOCO];
    uint8_t    sig[EC_SIG];
    tr31_cab_t cab;
    uint32_t   i;
    uint32_t   der_n = 0u;
    int        r = -1;

    keystore_rsa_apaga();
    if ((max < TR31_ASCII_EC) ||
        ((exportabilidade != KS_EXP_SIM) && (exportabilidade != KS_EXP_NAO) &&
         (exportabilidade != KS_EXP_SENSIVEL))) {
        return -1;
    }
    if (ecdsa_gera(g_rsa) != 0) {
        goto fim;
    }
    /* Teste de consistencia do par (FIPS 140-3): assinar com a chave nova
     * -- e ecdsa_assina() ja verifica com Q antes de devolver. O digest e
     * a propria chave publica: qualquer valor serve. */
    r = ecdsa_assina(g_rsa, &g_rsa[EC_BYTES], sig);
    if (r != 0) {
        if (r == -2) {
            erro_grave_marca();
        }
        goto fim;
    }
    r = -1;

    cab.uso[0]          = (uint8_t)'S';
    cab.uso[1]          = (uint8_t)'0';
    cab.algoritmo       = (uint8_t)KS_ALG_EC;
    cab.modo            = (uint8_t)KS_MODO_ASSINA;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = exportabilidade;
    if ((lmk_deriva_kb(kbek, kbak) != 0) ||
        (drbg_dispositivo_bytes(enchimento, sizeof enchimento) != 0) ||
        (pkcs8_ec_monta(g_rsa, g_der, (uint32_t)sizeof g_der, &der_n) != 0) ||
        (tr31_embrulha_n(kbek, kbak, &cab, g_der, (uint16_t)der_n,
                         enchimento, (uint8_t)sizeof enchimento,
                         saida, saida_n) != 0)) {
        goto fim;
    }
    for (i = 0u; i < EC_PUB; i++) {
        q[i] = g_rsa[EC_BYTES + i];
    }
    r = 0;
fim:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(enchimento, sizeof enchimento);
    wipe(sig, sizeof sig);
    keystore_rsa_apaga();
    return r;
}

/* ------------------------------------------------------------------
 * KEK -- troca de chaves com outra instituição (fase 5)
 * ------------------------------------------------------------------ */

int keystore_kek_deriva(ks_handle_t h, uint8_t precisa_modo,
                        uint8_t kbek[KS_KEY_MAX], uint8_t kbak[KS_KEY_MAX],
                        uint8_t *n)
{
    int     i = indice(h);
    uint8_t aes, tdes;

    if ((i < 0) || (kbek == 0) || (kbak == 0) || (n == 0)) {
        return -1;
    }
    *n = 0u;
    /* Só uma chave de USO 'K0' protege outra chave. Sem isso, qualquer
     * chave de dados com modo 'B' viraria KEK, e o que foi cifrado como
     * dado poderia ser apresentado como chave -- a confusão de tipo que o
     * key block existe para fechar. AES-256 (versão D, a mesma derivação da
     * LMK) ou, desde a etapa 8.7, 3DES duplo ou triplo (versão B). */
    aes  = (uint8_t)((g_slots[i].algoritmo == KS_ALG_AES) &&
                     (g_slots[i].key_len == KS_KEY_MAX));
    tdes = (uint8_t)((g_slots[i].algoritmo == KS_ALG_TDES) &&
                     ((g_slots[i].key_len == TDES_CHAVE_2) ||
                      (g_slots[i].key_len == TDES_CHAVE_3)));
    if ((g_slots[i].uso[0] != (uint8_t)'K') ||
        (g_slots[i].uso[1] != (uint8_t)'0') || (!aes && !tdes)) {
        return -2;
    }
    /* 'E' embrulha (exportar), 'D' desembrulha (importar), 'B' os dois.
     * É a leitura que a norma dá ao `modo` de uma KEK. */
    if ((g_slots[i].modo != KS_MODO_AMBOS) &&
        (g_slots[i].modo != precisa_modo)) {
        return -3;
    }
    g_slots[i].contador_uso++;
    if (aes) {
        if (tr31_deriva(g_slots[i].chave, kbek, kbak) != 0) {
            return -1;
        }
    } else if (tr31b_deriva(g_slots[i].chave, g_slots[i].key_len,
                            kbek, kbak) != 0) {
        return -1;
    }
    *n = g_slots[i].key_len;
    return 0;
}

int keystore_kek_transporta(uint8_t n_kek, uint8_t algoritmo, uint8_t key_len)
{
    if (n_kek == KS_KEY_MAX) {
        return 1;           /* KEK AES-256: a mais forte deste equipamento */
    }
    if ((n_kek != TDES_CHAVE_2) && (n_kek != TDES_CHAVE_3)) {
        return 0;
    }
    return ((algoritmo == KS_ALG_TDES) && (key_len <= n_kek)) ? 1 : 0;
}

/* O mesmo que embrulha_slot(), em versão B, sob subchaves 3DES de `n`
 * bytes. FRONTEIRA: dentro. */
static int embrulha_slot_b(int i, const uint8_t *kbek, const uint8_t *kbak,
                           uint8_t n, char *saida, uint32_t *saida_n)
{
    uint8_t    enchimento[TR31B_BLOCO];
    tr31_cab_t cab;
    int        r = -1;

    if (drbg_dispositivo_bytes(enchimento, sizeof enchimento) == 0) {
        cab.uso[0]          = g_slots[i].uso[0];
        cab.uso[1]          = g_slots[i].uso[1];
        cab.algoritmo       = g_slots[i].algoritmo;
        cab.modo            = g_slots[i].modo;
        cab.versao_chave[0] = (uint8_t)'0';
        cab.versao_chave[1] = (uint8_t)'0';
        cab.exportabilidade = g_slots[i].exportabilidade;
        r = tr31b_embrulha(kbek, kbak, n, &cab, g_slots[i].chave,
                           g_slots[i].key_len, enchimento,
                           (uint8_t)sizeof enchimento, saida, saida_n);
    }
    wipe(enchimento, sizeof enchimento);
    return r;
}

int keystore_embrulha_kek(ks_handle_t h, const uint8_t kbek[KS_KEY_MAX],
                          const uint8_t kbak[KS_KEY_MAX], uint8_t n,
                          char *saida, uint32_t *saida_n)
{
    int i = indice(h);

    if ((i < 0) || (kbek == 0) || (kbak == 0) || (saida == 0) ||
        (saida_n == 0)) {
        return -1;
    }
    if (!exportavel(i)) {
        return -2;
    }
    if (!keystore_kek_transporta(n, g_slots[i].algoritmo,
                                 g_slots[i].key_len)) {
        return -3;
    }
    if (n == KS_KEY_MAX) {
        return (embrulha_slot(i, kbek, kbak, saida, saida_n) == 0) ? 0 : -1;
    }
    return (embrulha_slot_b(i, kbek, kbak, n, saida, saida_n) == 0) ? 0 : -1;
}

int keystore_embrulha_lmk(ks_handle_t h, char *saida, uint32_t *saida_n)
{
    uint8_t kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    int     i = indice(h);
    int     r = -1;

    if ((i < 0) || (saida == 0) || (saida_n == 0)) {
        return -1;
    }
    /* Sem checar `exportabilidade`: um bloco sob a LMK só abre dentro
     * deste dispositivo, então guardá-lo no banco do host não é exportar
     * -- é o mesmo argumento do K0. Uma chave 'N' recebida de outra
     * instituição precisa poder ser guardada aqui. */
    if (lmk_deriva_kb(kbek, kbak) == 0) {
        r = (embrulha_slot(i, kbek, kbak, saida, saida_n) == 0) ? 0 : -1;
    }
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    return r;
}

/* ------------------------------------------------------------------
 * Registro persistente -- fase 4
 *
 * O corpo do registro que fw/src/persist.c grava na flash:
 *
 *   lmk(32) || kcv_lmk(3) || n(1) || n x [ indice(1) || key block(144) ]
 *
 * A LMK vai EM CLARO: a regiao da flash e tratada como memoria segura
 * (decisao de 2026-10-15, CLAUDE.md regra 2). Os slots vao EMBRULHADOS
 * sob ela, como key blocks X9.143 -- e o modelo da categoria: a chave
 * mestra vive na memoria segura, e as chaves de trabalho so existem fora
 * do uso embrulhadas pela chave mestra.
 *
 * Vive aqui porque e o unico arquivo que tem os bytes. persist.c recebe
 * um buffer e o grava, sem saber o que tem dentro.
 *
 * ⚠ `exportabilidade = 'N'` NAO impede a chave de ir para o registro.
 * Ela nao sai da fronteira: a flash, nesta decisao, e dentro. Por isso
 * este caminho NAO passa por keystore_exporta().
 * ------------------------------------------------------------------ */

#define REG_ENTRADA  (1u + TR31_ASCII_MAX)

/* O comprimento do bloco de uma entrada, lido dos 4 digitos do cabecalho.
 * 0 se nao for numero ou passar da entrada: tr31_desembrulha() recusa. */
static uint32_t reg_bloco_n(const uint8_t *e)
{
    uint32_t n = 0u, k;

    for (k = 1u; k <= 4u; k++) {
        if ((e[k] < (uint8_t)'0') || (e[k] > (uint8_t)'9')) {
            return 0u;
        }
        n = n * 10u + (uint32_t)(e[k] - (uint8_t)'0');
    }
    return (n <= TR31_ASCII_MAX) ? n : 0u;
}

int keystore_registro_monta(uint8_t *buf, uint32_t max, uint32_t *n)
{
    uint8_t    kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint32_t   i, pos, kb_n = 0u;
    uint8_t    cont = 0u;
    int        r = -1;

    if ((buf == 0) || (n == 0) || !lmk_completa() ||
        (max < KS_REGISTRO_MAX)) {
        return -1;
    }
    for (i = 0u; i < KS_KEY_MAX; i++) {
        buf[i] = g_lmk[i];
    }
    for (i = 0u; i < KS_KCV_LEN; i++) {
        buf[KS_KEY_MAX + i] = g_lmk_kcv[i];
    }
    pos = KS_KEY_MAX + KS_KCV_LEN + 1u;

    if (lmk_deriva_kb(kbek, kbak) != 0) {
        goto fim;
    }
    for (i = 0u; i < KS_N_SLOTS; i++) {
        if (!g_slots[i].em_uso) {
            continue;
        }
        buf[pos] = (uint8_t)i;
        if ((embrulha_slot((int)i, kbek, kbak, (char *)&buf[pos + 1u],
                           &kb_n) != 0) ||
            (kb_n > TR31_ASCII_MAX)) {
            goto fim;
        }
        /* Etapa 8.7: o bloco de uma chave 3DES tem 112 caracteres, e a
         * entrada continua com 144. O resto vai com '0'; o comprimento
         * verdadeiro esta no cabecalho do bloco, e e ele que a carga le. */
        while (kb_n < TR31_ASCII_MAX) {
            buf[pos + 1u + kb_n] = (uint8_t)'0';
            kb_n++;
        }
        pos += REG_ENTRADA;
        cont++;
    }
    buf[KS_KEY_MAX + KS_KCV_LEN] = cont;
    *n = pos;
    r = 0;

fim:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    if (r != 0) {
        wipe(buf, max);
    }
    return r;
}

int keystore_registro_carrega(const uint8_t *buf, uint32_t n)
{
    uint8_t    kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t    chave[TR31_CHAVE_MAX];
    uint8_t    kcv[KS_KCV_LEN];
    uint8_t    klen = 0u;
    tr31_cab_t cab;
    uint32_t   i, pos, cont;
    int        r = -1;

    keystore_init();

    if ((buf == 0) || (n < KS_KEY_MAX + KS_KCV_LEN + 1u)) {
        return -1;
    }
    cont = buf[KS_KEY_MAX + KS_KCV_LEN];
    if ((cont > KS_N_SLOTS) ||
        (n != KS_KEY_MAX + KS_KCV_LEN + 1u + cont * REG_ENTRADA)) {
        return -1;
    }

    /* A LMK so e aceita se o KCV recalculado bater com o gravado. Nao e
     * defesa contra ataque -- a flash e tratada como segura -- e
     * conferencia de integridade: um bit trocado na LMK mudaria TODAS as
     * chaves que ela protege, e o operador descobriria pelo pior caminho. */
    if (keystore_kcv(buf, KS_KEY_MAX, kcv) != 0) {
        goto fim;
    }
    if ((kcv[0] != buf[KS_KEY_MAX]) || (kcv[1] != buf[KS_KEY_MAX + 1u]) ||
        (kcv[2] != buf[KS_KEY_MAX + 2u])) {
        goto fim;
    }
    for (i = 0u; i < KS_KEY_MAX; i++) {
        g_lmk[i] = buf[i];
    }
    for (i = 0u; i < KS_KCV_LEN; i++) {
        g_lmk_kcv[i] = kcv[i];
    }
    g_lmk_comps = LMK_N_COMPONENTES;

    if (lmk_deriva_kb(kbek, kbak) != 0) {
        goto fim;
    }
    pos = KS_KEY_MAX + KS_KCV_LEN + 1u;
    for (i = 0u; i < cont; i++, pos += REG_ENTRADA) {
        if (buf[pos] >= KS_N_SLOTS) {
            goto fim;                   /* nunca restaurar no slot efemero */
        }
        if (tr31_desembrulha(kbek, kbak, (const char *)&buf[pos + 1u],
                             reg_bloco_n(&buf[pos + 1u]), &cab, chave,
                             &klen) != 0) {
            goto fim;
        }
        /* Chave 3DES: a instalacao calcula o KCV com o motor, entao o
         * autoteste de primeiro uso roda antes. Reprovado, a carga falha
         * inteira, como com um bloco ruim. */
        if ((cab.algoritmo == (uint8_t)KS_ALG_TDES) &&
            (kat_primeiro_uso(KAT_FALHA_TDES) != 0)) {
            goto fim;
        }
        /* Chave AES-128 (a BDK do DUKPT AES): o KCV usa o motor AES-128. */
        if ((cab.algoritmo == (uint8_t)KS_ALG_AES) && (klen == AES128_CHAVE) &&
            (kat_primeiro_uso(KAT_FALHA_DUKPT_AES) != 0)) {
            goto fim;
        }
        if (instala_em(buf[pos], cab.uso, cab.algoritmo, cab.modo,
                       cab.exportabilidade, chave, klen)
            == KS_HANDLE_INVALIDO) {
            goto fim;
        }
        wipe(chave, sizeof chave);
    }
    r = 0;

fim:
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(chave, sizeof chave);
    wipe(kcv, sizeof kcv);
    if (r != 0) {
        keystore_init();     /* tudo ou nada */
    }
    return r;
}
