/* fw/src/hsm_cfs.c -- driver do coprocessador criptografico (CFS)
 *
 * FRONTEIRA: dentro. Ver hsm_cfs.h.
 *
 * Contrato de hardware: rtl/crypto/hsm_cfs.v. Verificado ponta a ponta por
 * sim/tb/tb_cfs.v, que replica os vetores do NIST atraves do MESMO mapa de
 * registradores que este arquivo usa.
 */
#include <neorv32.h>

#include "hsm_cfs.h"
#include "wipe.h"

/* ------------------------------------------------------------------ */
/* Mapa de registradores -- indices de PALAVRA (offset de byte / 4)     */
/* Espelha o cabecalho de rtl/crypto/hsm_cfs.v.                         */
/* ------------------------------------------------------------------ */
#define R_ID        0u    /* 0x000 */
#define R_STATUS    1u    /* 0x004 */
#define R_CTRL      2u    /* 0x008 */
#define R_KEY       8u    /* 0x020, 8 palavras */
#define R_BLOCK    16u    /* 0x040, 4 palavras */
#define R_RESULT   20u    /* 0x050, 4 palavras */
#define R_SBLOCK   32u    /* 0x080, 16 palavras */
#define R_DIGEST   48u    /* 0x0C0, 8 palavras */
#define R_DNA_LO   64u    /* 0x100 */
#define R_DNA_HI   65u    /* 0x104 */

#define C_AES_INIT  0x01u
#define C_AES_NEXT  0x02u
#define C_AES_ENC   0x04u
#define C_SHA_INIT  0x08u
#define C_SHA_NEXT  0x10u
#define C_WIPE      0x20u

#define S_AES_BUSY  0x01u
#define S_AES_VALID 0x02u
#define S_SHA_BUSY  0x04u
#define S_SHA_VALID 0x08u
#define S_DNA_VALID 0x10u
#define S_WIPE_BUSY 0x20u

/* Um bloco de AES leva ~60 ciclos e o wipe algumas centenas. Este limite
 * e tres ordens de grandeza acima do pior caso e existe por um motivo so:
 * hardware quebrado nao pode travar o dispositivo. Um HSM mudo e uma
 * negacao de servico; um HSM que responde erro e diagnosticavel. */
#define CFS_SPIN_LIMIT  100000u

/* ------------------------------------------------------------------ */
/* Ordem dos bytes                                                     */
/*                                                                     */
/* O coprocessador recebe cada valor com a palavra MAIS SIGNIFICATIVA   */
/* primeiro, como nos vetores do NIST. A CPU e RISC-V little-endian.    */
/* Montar a palavra byte a byte e obrigatorio: um memcpy compilaria e   */
/* falharia em todos os KAT -- que e, por sorte, o melhor desfecho      */
/* possivel para esse tipo de erro.                                    */
/* ------------------------------------------------------------------ */
static uint32_t be32_load(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | ((uint32_t)p[3]);
}

static void be32_store(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

static void reg_write_be(uint32_t first, const uint8_t *src, uint32_t words)
{
    for (uint32_t i = 0u; i < words; i++) {
        NEORV32_CFS->REG[first + i] = be32_load(src + 4u * i);
    }
}

static void reg_read_be(uint32_t first, uint8_t *dst, uint32_t words)
{
    for (uint32_t i = 0u; i < words; i++) {
        be32_store(dst + 4u * i, NEORV32_CFS->REG[first + i]);
    }
}

/* Espera os bits de 'mask' zerarem em STATUS.
 *
 * O bit de BUSY sobe junto com o comando -- o hardware resolve isso, e nao
 * este laco. Ver "O BIT DE BUSY" no cabecalho de rtl/crypto/hsm_cfs.v: o
 * handshake por 'ready' do core e o que fez o tb_sha256_kat reprovar com
 * digests deslocados de um. Aqui nao ha como cometer o mesmo erro. */
static int cfs_wait(uint32_t mask)
{
    for (uint32_t i = 0u; i < CFS_SPIN_LIMIT; i++) {
        if ((NEORV32_CFS->REG[R_STATUS] & mask) == 0u) {
            return 0;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */

int hsm_cfs_present(void)
{
    if (neorv32_cfs_available() == 0) {
        return 0;
    }
    return (NEORV32_CFS->REG[R_ID] == HSM_CFS_ID_MAGIC) ? 1 : 0;
}

int hsm_cfs_dna(uint8_t out[HSM_DNA_LEN])
{
    if ((NEORV32_CFS->REG[R_STATUS] & S_DNA_VALID) == 0u) {
        return -1;
    }

    /* 57 bits em 8 bytes, big-endian. Os 7 bits mais altos sao zero por
     * construcao -- o hardware ja mascara DNA_HI. */
    be32_store(&out[0], NEORV32_CFS->REG[R_DNA_HI]);
    be32_store(&out[4], NEORV32_CFS->REG[R_DNA_LO]);
    return 0;
}

/* FRONTEIRA: dentro. Recebe chave em claro. */
int hsm_cfs_aes_key(const uint8_t key[HSM_AES_KEY_LEN])
{
    reg_write_be(R_KEY, key, HSM_AES_KEY_LEN / 4u);
    NEORV32_CFS->REG[R_CTRL] = C_AES_INIT;
    return cfs_wait(S_AES_BUSY);
}

/* FRONTEIRA: dentro. Opera sob a chave carregada por hsm_cfs_aes_key(). */
int hsm_cfs_aes_block(const uint8_t in[HSM_AES_BLOCK_LEN],
                      uint8_t out[HSM_AES_BLOCK_LEN],
                      int encrypt)
{
    reg_write_be(R_BLOCK, in, HSM_AES_BLOCK_LEN / 4u);
    NEORV32_CFS->REG[R_CTRL] = C_AES_NEXT | (encrypt ? C_AES_ENC : 0u);

    if (cfs_wait(S_AES_BUSY) != 0) {
        /* Nao devolver o buffer com conteudo indefinido: sob timeout o
         * registrador de resultado nao tem significado, e um chamador
         * distraido o trataria como criptograma. */
        wipe(out, HSM_AES_BLOCK_LEN);
        return -1;
    }

    reg_read_be(R_RESULT, out, HSM_AES_BLOCK_LEN / 4u);
    return 0;
}

int hsm_cfs_sha_block(const uint8_t block[HSM_SHA_BLOCK_LEN], int first)
{
    reg_write_be(R_SBLOCK, block, HSM_SHA_BLOCK_LEN / 4u);
    NEORV32_CFS->REG[R_CTRL] = first ? C_SHA_INIT : C_SHA_NEXT;
    return cfs_wait(S_SHA_BUSY);
}

int hsm_cfs_sha_digest(uint8_t out[HSM_SHA_DIGEST_LEN])
{
    if (cfs_wait(S_SHA_BUSY) != 0) {
        wipe(out, HSM_SHA_DIGEST_LEN);
        return -1;
    }
    reg_read_be(R_DIGEST, out, HSM_SHA_DIGEST_LEN / 4u);
    return 0;
}

/* FRONTEIRA: dentro. Apaga material de chave do hardware. */
int hsm_cfs_wipe(void)
{
    NEORV32_CFS->REG[R_CTRL] = C_WIPE;
    return cfs_wait(S_WIPE_BUSY);
}

/* =====================================================================
 * TRNG -- fonte de ruido, retrato bruto e health tests de partida
 *
 * FRONTEIRA: tudo abaixo esta DENTRO. hsm_trng_snapshot() devolve amostra
 * BRUTA da fonte de ruido, que e o material mais sensivel deste bloco
 * depois da propria chave -- quem preve a fonte preve a semente, e quem
 * preve a semente preve toda chave gerada. Nao existe, e nao pode passar
 * a existir, comando de host que chegue ate aqui.
 * ===================================================================== */

#define R_TRNG_CTRL    68u   /* 0x110 */
#define R_TRNG_STATUS  69u   /* 0x114 */
#define R_TRNG_BYTE    70u   /* 0x118 */
#define R_TRNG_DIAG    71u   /* 0x11C */
#define R_TRNG_SNAP    96u   /* 0x180, 32 palavras */

#define C_TRNG_EN    0x1u
#define C_TRNG_SNAP  0x2u

void hsm_trng_enable(int on)
{
    NEORV32_CFS->REG[R_TRNG_CTRL] = on ? C_TRNG_EN : 0u;
}

uint32_t hsm_trng_status(void)
{
    return NEORV32_CFS->REG[R_TRNG_STATUS];
}

int hsm_trng_byte(uint8_t *out)
{
    for (uint32_t i = 0u; i < CFS_SPIN_LIMIT; i++) {
        if ((NEORV32_CFS->REG[R_TRNG_STATUS] & HSM_TRNG_BYTE_VALID) != 0u) {
            *out = (uint8_t)(NEORV32_CFS->REG[R_TRNG_BYTE] & 0xFFu);
            return 0;
        }
    }
    *out = 0u;
    return -1;
}

int hsm_trng_snapshot(uint8_t out[HSM_TRNG_SNAP_BYTES])
{
    NEORV32_CFS->REG[R_TRNG_CTRL] = C_TRNG_EN | C_TRNG_SNAP;

    for (uint32_t i = 0u; i < CFS_SPIN_LIMIT; i++) {
        if ((NEORV32_CFS->REG[R_TRNG_STATUS] & HSM_TRNG_SNAP_READY) != 0u) {
            /* Palavra 0 traz as amostras mais antigas; dentro da palavra,
             * o bit 31 e a mais antiga. Manter a ordem temporal e
             * obrigatorio: RCT e APT sao definidos sobre a SEQUENCIA, e
             * uma ordem trocada testa algo que nunca aconteceu. */
            reg_read_be(R_TRNG_SNAP, out, HSM_TRNG_SNAP_BYTES / 4u);
            return 0;
        }
    }
    wipe(out, HSM_TRNG_SNAP_BYTES);
    return -1;
}

/* Amostra i do retrato, na ordem em que a fonte produziu. */
static unsigned bit_em(const uint8_t *p, unsigned i)
{
    return (unsigned)((p[i >> 3] >> (7u - (i & 7u))) & 1u);
}

/* SP 800-90B 4.4.1 -- Repetition Count Test.
 *
 * A = amostra anterior, B = quantas vezes se repetiu. B >= C reprova.
 * Pega o modo de falha catastrofico: a fonte travou num valor. */
int hsm_health_rct(const uint8_t *amostras, unsigned bits)
{
    unsigned a, b, i;

    if (bits == 0u) {
        return -1;
    }

    a = bit_em(amostras, 0u);
    b = 1u;

    for (i = 1u; i < bits; i++) {
        unsigned x = bit_em(amostras, i);
        if (x == a) {
            b++;
            if (b >= HSM_RCT_CUTOFF) {
                return -1;
            }
        } else {
            a = x;
            b = 1u;
        }
    }
    return 0;
}

/* SP 800-90B 4.4.2 -- Adaptive Proportion Test.
 *
 * A cada janela de W amostras, A = a primeira; conta quantas das W sao
 * iguais a A. >= C reprova. Pega a fonte que NAO travou mas ficou
 * enviesada -- ela varia o tempo todo, passa no RCT, e nao tem a entropia
 * que se assumiu ao dimensionar a semente. */
int hsm_health_apt(const uint8_t *amostras, unsigned bits)
{
    unsigned i;

    if (bits < HSM_APT_WINDOW) {
        return -1;      /* janela incompleta nao e "passou" */
    }

    for (i = 0u; i + HSM_APT_WINDOW <= bits; i += HSM_APT_WINDOW) {
        unsigned a = bit_em(amostras, i);
        unsigned b = 1u;
        unsigned k;

        for (k = 1u; k < HSM_APT_WINDOW; k++) {
            if (bit_em(amostras, i + k) == a) {
                b++;
                if (b >= HSM_APT_CUTOFF) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* Teste de partida -- SP 800-90B 4.3.
 *
 * Falhou: o chamador leva o dispositivo a TAMPERED. Nao ha uso seguro de
 * uma fonte reprovada, e "tentar de novo" e a resposta errada: uma fonte
 * intermitente que passa na segunda tentativa continua sendo uma fonte
 * que nao se pode caracterizar. */
int hsm_trng_startup(void)
{
    uint8_t retrato[HSM_TRNG_SNAP_BYTES];
    uint32_t st;
    int r = 0;

    hsm_trng_enable(1);

    if (hsm_trng_snapshot(retrato) != 0) {
        r = -1;
    }

    /* Veredito do hardware, que viu TODAS as amostras desde que a fonte
     * ligou -- nao so as 1024 do retrato. */
    st = hsm_trng_status();
    if ((st & (HSM_TRNG_RCT_FAIL | HSM_TRNG_APT_FAIL)) != 0u) {
        r = -1;
    }

    /* Veredito do firmware, sobre o retrato. Dois vereditos independentes
     * sobre a mesma norma; discordancia denuncia erro de interpretacao. */
    if (r == 0 && hsm_health_rct(retrato, HSM_TRNG_SNAP_BITS) != 0) {
        r = -1;
    }
    if (r == 0 && hsm_health_apt(retrato, HSM_TRNG_SNAP_BITS) != 0) {
        r = -1;
    }

    /* O retrato e amostra bruta da fonte. Some da pilha antes de sair,
     * com barreira -- um memset simples aqui pode ser removido pelo
     * compilador, que e exatamente o caso que CLAUDE.md descreve. */
    wipe(retrato, sizeof retrato);

    if (r != 0) {
        hsm_trng_enable(0);
    }
    return r;
}
