/* fw/src/kat.c -- POST: known-answer tests no boot
 *
 * FRONTEIRA: dentro. Ver o cabeçalho de kat.h.
 *
 * Os vetores vêm de fw/include/kat_vectors.h, GERADO por scripts/mkkat.py a
 * partir de vectors/. Nenhum número aqui foi digitado à mão -- essa é a
 * única coisa que sustenta a regra inviolável nº 5: "se um KAT falha, o bug
 * está no código, não no vetor".
 */
#include "kat.h"
#include "kat_vectors.h"
#include "cmac.h"
#include "drbg.h"
#include "hsm_cfs.h"
#include "keystore.h"
#include "sha.h"
#include "tr31.h"
#include "wipe.h"

static unsigned g_ultimo = KAT_FALHA_AES  | KAT_FALHA_SHA  | KAT_FALHA_HMAC |
                           KAT_FALHA_CMAC | KAT_FALHA_DRBG | KAT_FALHA_TRNG |
                           KAT_FALHA_KS   | KAT_FALHA_TR31;

/* Comparação de tempo constante.
 *
 * Aqui não há segredo a proteger -- os vetores são públicos. Está assim
 * porque a mesma função vai comparar KCV e MAC na fase 3, e ter DUAS
 * comparações no firmware, uma segura e uma não, é como se escolhe a
 * errada por engano. Uma só, sempre a segura. */
static int iguais(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint8_t  d = 0u;
    uint32_t i;
    for (i = 0u; i < n; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return (d == 0u) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
static unsigned kat_aes(void)
{
    uint8_t saida[HSM_AES_BLOCK_LEN];
    unsigned falha = 0u;

    /* Vetor 0: cifra. Vetor 1: decifra. Os dois caminhos porque a
     * expansão de chave inversa é código diferente no core -- um AES que
     * cifra certo e decifra errado é um modo de falha real. */
    if (hsm_cfs_aes_key(kat_aes0_key) != 0) {
        falha = KAT_FALHA_AES;
    } else if (hsm_cfs_aes_block(kat_aes0_in, saida, KAT_AES0_CIFRA) != 0) {
        falha = KAT_FALHA_AES;
    } else if (!iguais(saida, kat_aes0_out, HSM_AES_BLOCK_LEN)) {
        falha = KAT_FALHA_AES;
    }

    if (falha == 0u) {
        if (hsm_cfs_aes_key(kat_aes1_key) != 0) {
            falha = KAT_FALHA_AES;
        } else if (hsm_cfs_aes_block(kat_aes1_in, saida, KAT_AES1_CIFRA) != 0) {
            falha = KAT_FALHA_AES;
        } else if (!iguais(saida, kat_aes1_out, HSM_AES_BLOCK_LEN)) {
            falha = KAT_FALHA_AES;
        }
    }

    wipe(saida, sizeof saida);
    return falha;
}

static unsigned kat_sha(void)
{
    uint8_t md[HSM_SHA256_LEN];
    unsigned falha = 0u;

    if (hsm_sha256(kat_sha0_msg, KAT_SHA0_LEN, md) != 0 ||
        !iguais(md, kat_sha0_md, HSM_SHA256_LEN)) {
        falha = KAT_FALHA_SHA;
    }
    if (falha == 0u) {
        if (hsm_sha256(kat_sha1_msg, KAT_SHA1_LEN, md) != 0 ||
            !iguais(md, kat_sha1_md, HSM_SHA256_LEN)) {
            falha = KAT_FALHA_SHA;
        }
    }

    wipe(md, sizeof md);
    return falha;
}

static unsigned kat_hmac(void)
{
    uint8_t mac[HSM_SHA256_LEN];
    unsigned falha = 0u;

#define TESTA_HMAC(i)                                                     \
    do {                                                                  \
        if (falha == 0u) {                                                \
            if (hsm_hmac_sha256(kat_hmac##i##_key, KAT_HMAC##i##_KEYLEN,  \
                                kat_hmac##i##_data, KAT_HMAC##i##_DATALEN,\
                                mac) != 0 ||                              \
                !iguais(mac, kat_hmac##i##_mac, HSM_SHA256_LEN)) {        \
                falha = KAT_FALHA_HMAC;                                   \
            }                                                             \
        }                                                                 \
    } while (0)

    TESTA_HMAC(0);
    TESTA_HMAC(1);
    TESTA_HMAC(2);      /* chave MAIOR que o bloco -- o ramo esquecido */
#undef TESTA_HMAC

    wipe(mac, sizeof mac);
    return falha;
}

/* CMAC-AES-256.
 *
 * Tres classes porque o algoritmo tem tres caminhos -- mensagem vazia,
 * alinhada ao bloco (usa K1) e com padding (usa K2). Um vetor so nao
 * distingue K1 de K2: uma implementacao que use sempre o mesmo subkey
 * passa em metade dos casos.
 *
 * Compara so os primeiros TAGLEN bytes: o arquivo do CAVP traz tags
 * truncadas. Ver o cabecalho de kat_vectors.h. */
static unsigned kat_cmac(void)
{
    uint8_t  tag[CMAC_TAG_LEN];
    unsigned falha = 0u;

#define TESTA_CMAC(i)                                                      \
    do {                                                                   \
        if (falha == 0u) {                                                 \
            if (cmac_aes256(kat_cmac##i##_key,                             \
                            kat_cmac##i##_msg, KAT_CMAC##i##_MSGLEN,       \
                            tag) != 0 ||                                   \
                !iguais(tag, kat_cmac##i##_mac, KAT_CMAC##i##_TAGLEN)) {   \
                falha = KAT_FALHA_CMAC;                                    \
            }                                                              \
        }                                                                  \
    } while (0)

    TESTA_CMAC(0);
    TESTA_CMAC(1);
    TESTA_CMAC(2);
#undef TESTA_CMAC

    wipe(tag, sizeof tag);
    return falha;
}

/* CTR_DRBG.
 *
 * O fluxo do teste do CAVP não é óbvio a partir do .rsp e errá-lo dá um
 * resultado errado que parece um bug de implementação:
 *
 *   instantiate(entropia, nonce, personalização)
 *   generate(addl1)  -> DESCARTA
 *   generate(addl2)  -> compara
 *
 * A primeira geração existe justamente para exercitar o update interno.
 * Comparar a primeira saída reprova uma implementação correta. */
static unsigned um_drbg(const uint8_t *ent, uint32_t ent_n,
                        const uint8_t *nonce, uint32_t nonce_n,
                        const uint8_t *pers, uint32_t pers_n,
                        const uint8_t *a1, uint32_t a1_n,
                        const uint8_t *a2, uint32_t a2_n,
                        const uint8_t *esperado, uint32_t esperado_n)
{
    drbg_estado_t st;
    uint8_t       saida[64];
    unsigned      falha = 0u;

    if (esperado_n > sizeof saida) {
        return KAT_FALHA_DRBG;
    }

    if (drbg_instantiate(&st, ent, ent_n, nonce, nonce_n, pers, pers_n) != 0) {
        falha = KAT_FALHA_DRBG;
    } else if (drbg_generate(&st, saida, esperado_n, a1, a1_n) != 0) {
        falha = KAT_FALHA_DRBG;
    } else if (drbg_generate(&st, saida, esperado_n, a2, a2_n) != 0) {
        falha = KAT_FALHA_DRBG;
    } else if (!iguais(saida, esperado, esperado_n)) {
        falha = KAT_FALHA_DRBG;
    }

    drbg_uninstantiate(&st);
    wipe(saida, sizeof saida);
    return falha;
}

static unsigned kat_drbg(void)
{
    unsigned falha = 0u;

#define TESTA_DRBG(i)                                                      \
    do {                                                                   \
        if (falha == 0u) {                                                 \
            falha |= um_drbg(kat_drbg##i##_entropia, KAT_DRBG##i##_ENTROPIA_N, \
                             kat_drbg##i##_nonce,    KAT_DRBG##i##_NONCE_N,    \
                             kat_drbg##i##_pers,     KAT_DRBG##i##_PERS_N,     \
                             kat_drbg##i##_addl1,    KAT_DRBG##i##_ADDL1_N,    \
                             kat_drbg##i##_addl2,    KAT_DRBG##i##_ADDL2_N,    \
                             kat_drbg##i##_esperado, KAT_DRBG##i##_ESPERADO_N);\
        }                                                                  \
    } while (0)

    TESTA_DRBG(0);
    TESTA_DRBG(1);
    TESTA_DRBG(2);
#undef TESTA_DRBG

    return falha;
}

/* Fonte de entropia: testes de partida da SP 800-90B.
 *
 * Não é KAT -- não existe "resposta conhecida" para uma fonte física, e
 * exigir uma seria exigir que ela não fosse aleatória. O que se verifica é
 * que a fonte LIGA, produz, e passa nos health tests de partida. */
static unsigned kat_trng(void)
{
    return (hsm_trng_startup() == 0) ? 0u : KAT_FALHA_TRNG;
}


/* Key store -- teste de FUNCAO CRITICA, nao KAT. Ver o cabecalho de kat.h.
 *
 * A resposta conhecida do KCV nao precisa de vetor novo, e isso vale
 * explicar: KCV e AES-ECB da chave sobre um bloco de ZEROS, e o vetor
 * ECBKeySbox256 do CAVP tem exatamente PLAINTEXT = 0. Entao o KCV da
 * chave daquele vetor E, por definicao, os tres primeiros bytes do
 * criptograma dele -- que ja esta em kat_vectors.h como kat_aes1_in.
 *
 * Procedencia do NIST, zero bytes a mais na IMEM, e nenhum numero
 * calculado por este projeto.
 */
static unsigned kat_keystore(void)
{
    ks_handle_t h_nao, h_sim, h_cifra;
    ks_info_t   info;
    uint8_t     saida[KS_KEY_MAX];
    unsigned    falha = 0u;

    keystore_init();

    /* --- instala com exportabilidade 'N' e confere o KCV --- */
    h_nao = keystore_instala((const uint8_t *)KS_USO_DADOS, KS_ALG_AES,
                             KS_MODO_AMBOS, KS_EXP_NAO,
                             kat_aes1_key, KS_KEY_MAX);
    if (h_nao == KS_HANDLE_INVALIDO) {
        falha = KAT_FALHA_KS;
    } else if (keystore_info(h_nao, &info) != 0) {
        falha = KAT_FALHA_KS;
    } else if (!iguais(info.kcv, kat_aes1_in, KS_KCV_LEN)) {
        falha = KAT_FALHA_KS;
    }

    /* --- 'N' NAO pode sair. E a propriedade que mais importa aqui: se
     *     esta falhar, o dispositivo entrega chave marcada como nao
     *     exportavel e nada a jusante percebe. --- */
    if (falha == 0u) {
        if (keystore_exporta(h_nao, saida) != 0u) {
            falha = KAT_FALHA_KS;
        }
    }

    /* --- 'E' pode, e volta igual --- */
    if (falha == 0u) {
        h_sim = keystore_instala((const uint8_t *)KS_USO_KEK, KS_ALG_AES,
                                 KS_MODO_AMBOS, KS_EXP_SIM,
                                 kat_aes1_key, KS_KEY_MAX);
        if (h_sim == KS_HANDLE_INVALIDO) {
            falha = KAT_FALHA_KS;
        } else if (keystore_exporta(h_sim, saida) != KS_KEY_MAX) {
            falha = KAT_FALHA_KS;
        } else if (!iguais(saida, kat_aes1_key, KS_KEY_MAX)) {
            falha = KAT_FALHA_KS;
        }
    }

    /* --- separacao de uso: chave so de cifrar recusa decifrar --- */
    if (falha == 0u) {
        h_cifra = keystore_instala((const uint8_t *)KS_USO_DADOS, KS_ALG_AES,
                                   KS_MODO_CIFRA, KS_EXP_NAO,
                                   kat_aes1_key, KS_KEY_MAX);
        if (h_cifra == KS_HANDLE_INVALIDO) {
            falha = KAT_FALHA_KS;
        } else if (keystore_usa_aes(h_cifra, KS_MODO_CIFRA) != 0) {
            falha = KAT_FALHA_KS;
        } else if (keystore_usa_aes(h_cifra, KS_MODO_DECIFRA) == 0) {
            falha = KAT_FALHA_KS;        /* deveria ter recusado */
        }
    }

    /* --- header invalido e recusado: 3DES nao existe neste hardware --- */
    if (falha == 0u) {
        if (keystore_instala((const uint8_t *)KS_USO_DADOS, KS_ALG_3DES,
                             KS_MODO_AMBOS, KS_EXP_NAO,
                             kat_aes1_key, KS_KEY_MAX) != KS_HANDLE_INVALIDO) {
            falha = KAT_FALHA_KS;
        }
    }

    /* --- apagar de verdade: depois disso o handle nao resolve --- */
    if (falha == 0u) {
        if (keystore_apaga(h_nao) != 0) {
            falha = KAT_FALHA_KS;
        } else if (keystore_info(h_nao, &info) == 0) {
            falha = KAT_FALHA_KS;        /* handle morto ainda responde */
        }
    }

    /* Nao deixa material de teste para tras -- e PROVA que nao deixou.
     *
     * Nao ha bit de mascara livre para um teste proprio de zeroizacao (os
     * oito acabaram, ver kat.h), e nem faria sentido: isto e uma
     * propriedade do key store, e KAT_FALHA_KS ja e o bit dele.
     *
     * Vale mais do que parece. Depois deste ponto o firmware acabou de
     * escrever chave em quatro slots e apagar tudo; se a zeroizacao
     * tivesse um buraco -- um campo novo fora do laco, um wipe que o
     * compilador tivesse eliminado -- o boot seguinte comecaria com
     * material vivo na BRAM e nada denunciaria. */
    keystore_init();
    if (!keystore_prova_zeroizacao()) {
        falha = KAT_FALHA_KS;
    }
    wipe(saida, sizeof saida);
    (void)hsm_cfs_wipe();
    return falha;
}

unsigned kat_post(void)
{
    unsigned r = 0u;

    /* Ordem deliberada: do mais básico para o mais composto. AES é a base
     * do DRBG; SHA é a base do HMAC. Se o AES falhar, o DRBG também vai
     * falhar, e ver os dois bits acesos com o AES primeiro na lista diz
     * onde procurar. */
    r |= kat_aes();
    r |= kat_sha();
    r |= kat_hmac();
    r |= kat_cmac();
    r |= kat_drbg();
    r |= kat_trng();
    r |= kat_keystore();

    /* Key block X9.143 -- teste de funcao critica, como o key store.
     *
     * Depende de CMAC e de AES, entao vem depois dos dois: com os tres
     * bits acesos, o que interessa e o primeiro da lista. */
    if (tr31_selftest() != 0) {
        r |= KAT_FALHA_TR31;
    }

    /* O DRBG do dispositivo só é semeado depois que a fonte passou. Semear
     * a partir de uma fonte reprovada seria produzir chaves com entropia
     * desconhecida -- exatamente o que o health test existe para impedir. */
    if (r == KAT_OK) {
        if (drbg_dispositivo_semear() != 0) {
            r |= KAT_FALHA_DRBG;
        }
    }

    /* Os KAT deixaram material de teste no coprocessador: a chave expandida
     * do último vetor de AES ainda está no aes_key_mem. Limpar antes de
     * operar não é zelo, é higiene de fronteira. */
    (void)hsm_cfs_wipe();

    g_ultimo = r;
    return r;
}

unsigned kat_ultimo(void)
{
    return g_ultimo;
}
