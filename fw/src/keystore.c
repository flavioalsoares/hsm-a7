/* fw/src/keystore.c -- key store em BRAM
 *
 * FRONTEIRA: dentro, e é o bloco mais sensível do firmware. Ver o
 * cabeçalho de keystore.h para as decisões de projeto.
 */
#include "keystore.h"
#include "hsm_cfs.h"
#include "tr31.h"
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

/* Estáticos: vivem na DMEM, que é Block RAM. Regra 2 por construção. */
static slot_t  g_slots[KS_N_SLOTS];

static uint8_t g_lmk[KS_KEY_MAX];
static uint8_t g_lmk_comps;      /* quantos componentes entraram */
static uint8_t g_lmk_kcv[KS_KCV_LEN];

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

/* Handle 1..KS_N_SLOTS -> índice 0..KS_N_SLOTS-1, ou -1. */
static int indice(ks_handle_t h)
{
    if ((h == KS_HANDLE_INVALIDO) || (h > KS_N_SLOTS)) {
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
    /* Só AES: o coprocessador não faz 3DES e um slot marcado 'T' seria uma
     * chave que o dispositivo não sabe usar -- pior que recusar, porque
     * pareceria instalada. */
    if (algoritmo != KS_ALG_AES) {
        return 0;
    }
    if ((modo != KS_MODO_CIFRA) && (modo != KS_MODO_DECIFRA) &&
        (modo != KS_MODO_AMBOS) && (modo != KS_MODO_NENHUM)) {
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
    acc |= g_lmk_comps;

    return (acc == 0u) ? 1 : 0;
}

int keystore_zeroiza_tudo(void)
{
    keystore_init();
    return keystore_prova_zeroizacao() ? 0 : -1;
}

ks_handle_t keystore_instala(const uint8_t uso[2], uint8_t algoritmo,
                             uint8_t modo, uint8_t exportabilidade,
                             const uint8_t *chave, uint8_t key_len)
{
    uint32_t i;
    uint8_t  kcv[KS_KCV_LEN];
    slot_t  *s;

    if ((chave == 0) || (key_len != KS_KEY_MAX)) {
        return KS_HANDLE_INVALIDO;
    }
    if (!header_valido(uso, algoritmo, modo, exportabilidade)) {
        return KS_HANDLE_INVALIDO;
    }

    /* KCV antes de ocupar o slot: se o hardware falhar, nada foi alterado.
     * Instalar e depois descobrir que o KCV não sai deixaria um slot com
     * chave e sem meio de conferir. */
    if (keystore_kcv(chave, key_len, kcv) != 0) {
        wipe(kcv, sizeof kcv);
        return KS_HANDLE_INVALIDO;
    }

    for (i = 0u; i < KS_N_SLOTS; i++) {
        if (!g_slots[i].em_uso) {
            break;
        }
    }
    if (i == KS_N_SLOTS) {
        wipe(kcv, sizeof kcv);
        return KS_HANDLE_INVALIDO;       /* cheio */
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

int keystore_usa_aes(ks_handle_t h, uint8_t precisa_modo)
{
    int i = indice(h);
    if (i < 0) {
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

uint8_t keystore_exporta(ks_handle_t h, uint8_t out[KS_KEY_MAX])
{
    int     i = indice(h);
    uint8_t k;

    if ((i < 0) || (out == 0)) {
        return 0u;
    }

    /* O ponto único onde `exportabilidade` decide. Não há segundo caminho
     * para os bytes saírem do slot. */
    if (g_slots[i].exportabilidade == KS_EXP_NAO) {
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
    uint8_t i;

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
