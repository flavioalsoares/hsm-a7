/* fw/src/drbg.c -- CTR_DRBG AES-256 com derivation function
 *
 * NIST SP 800-90A secao 10.2. Ver o cabecalho de drbg.h para o porque de
 * cada peca.
 *
 * FRONTEIRA: dentro, e fundo. Todo buffer local aqui contem material
 * derivado de chave e sai zeroizado com barreira.
 *
 * ---------------------------------------------------------------------
 * O AES VEM DO COPROCESSADOR
 *
 * Todas as cifragens passam pelo CFS, que ja foi verificado contra 1620
 * vetores do CAVP. Nao ha AES em software neste firmware, e isso e
 * deliberado: uma segunda implementacao seria uma segunda chance de errar,
 * e ainda por cima uma que roda com a chave na RAM da CPU.
 *
 * Consequencia pratica: o CFS guarda UMA chave expandida por vez. O df usa
 * uma chave fixa e o gerador usa a chave do estado, entao trocar entre as
 * duas exige recarregar. Cada troca custa a expansao de chave. Foi medido
 * e nao importa aqui -- correcao antes de desempenho, que e o objetivo
 * declarado da fase (PLANO.md secao 3).
 */
#include "drbg.h"
#include "hsm_cfs.h"
#include "wipe.h"

/* ------------------------------------------------------------------ */

static void inc_v(uint8_t v[DRBG_OUTLEN])
{
    /* V = (V + 1) mod 2^128, big-endian. Vai-um propagando do fim. */
    uint32_t i = DRBG_OUTLEN;
    while (i > 0u) {
        i--;
        v[i]++;
        if (v[i] != 0u) {
            break;
        }
    }
}

/* Um bloco AES-256 ECB com a chave ja carregada no CFS. */
static int aes_bloco(const uint8_t entrada[16], uint8_t saida[16])
{
    return hsm_cfs_aes_block(entrada, saida, 1 /* cifra */);
}

/* Carrega chave no CFS e dispara a expansao. */
static int aes_chave(const uint8_t k[DRBG_KEYLEN])
{
    return hsm_cfs_aes_key(k);
}

/* ------------------------------------------------------------------
 * CTR_DRBG_Update -- SP 800-90A 10.2.1.2
 *
 *   temp = vazio
 *   enquanto len(temp) < seedlen:
 *       V = V + 1
 *       temp = temp || AES(Key, V)
 *   temp = temp XOR provided_data
 *   Key = 32 bytes a esquerda de temp
 *   V   = 16 bytes a direita de temp
 *
 * E aqui que mora a resistencia a backtracking: a Key que produziu a
 * saida anterior e sobrescrita por material derivado dela, e a derivacao
 * nao e invertivel.
 *
 * 'fornecido' tem SEMPRE seedlen bytes -- quando nao ha dado adicional, e
 * um bloco de zeros, e o XOR com zero deixa temp intacto. A norma escreve
 * assim de proposito: um unico caminho de codigo, sem ramo condicional
 * mexendo em estado de chave.
 * ------------------------------------------------------------------ */
static int ctr_drbg_update(drbg_estado_t *st, const uint8_t fornecido[DRBG_SEEDLEN])
{
    uint8_t  temp[DRBG_SEEDLEN];
    uint32_t i;
    int      r = 0;

    if (aes_chave(st->key) != 0) {
        r = -1;
        goto fim;
    }

    for (i = 0u; i < DRBG_SEEDLEN; i += DRBG_OUTLEN) {
        inc_v(st->v);
        if (aes_bloco(st->v, &temp[i]) != 0) {
            r = -1;
            goto fim;
        }
    }

    for (i = 0u; i < DRBG_SEEDLEN; i++) {
        temp[i] ^= fornecido[i];
    }

    for (i = 0u; i < DRBG_KEYLEN; i++) {
        st->key[i] = temp[i];
    }
    for (i = 0u; i < DRBG_OUTLEN; i++) {
        st->v[i] = temp[DRBG_KEYLEN + i];
    }

fim:
    wipe(temp, sizeof temp);
    return r;
}

/* ------------------------------------------------------------------
 * BCC -- CBC-MAC com IV zero, usado pelo df (SP 800-90A 10.3.3)
 *
 * A chave ja precisa estar carregada no CFS pelo chamador.
 * ------------------------------------------------------------------ */
static int bcc(const uint8_t *dados, uint32_t n, uint8_t saida[DRBG_OUTLEN])
{
    uint8_t  encadeia[DRBG_OUTLEN];
    uint8_t  bloco[DRBG_OUTLEN];
    uint32_t i, j;
    int      r = 0;

    for (i = 0u; i < DRBG_OUTLEN; i++) {
        encadeia[i] = 0x00u;
    }

    for (i = 0u; i < n; i += DRBG_OUTLEN) {
        for (j = 0u; j < DRBG_OUTLEN; j++) {
            bloco[j] = encadeia[j] ^ dados[i + j];
        }
        if (aes_bloco(bloco, encadeia) != 0) {
            r = -1;
            goto fim;
        }
    }

    for (i = 0u; i < DRBG_OUTLEN; i++) {
        saida[i] = encadeia[i];
    }

fim:
    wipe(bloco, sizeof bloco);
    wipe(encadeia, sizeof encadeia);
    return r;
}

/* ------------------------------------------------------------------
 * Block_Cipher_df -- SP 800-90A 10.3.2
 *
 * Comprime material de entrada de tamanho arbitrario em exatamente
 * seedlen bytes, espalhando a entropia por todo o resultado.
 *
 *   S = L || N || entrada || 0x80, com zeros ate multiplo de 16
 *       L = len(entrada) em bytes, 32 bits big-endian
 *       N = bytes a devolver,      32 bits big-endian
 *
 *   K = 00 01 02 ... 1F        (chave FIXA, e publica -- ver abaixo)
 *   temp = BCC(K, IV_0 || S) || BCC(K, IV_1 || S) || ...
 *          com IV_i = i em 32 bits big-endian, preenchido com zeros
 *
 *   K' = 32 bytes a esquerda de temp
 *   X  = 16 bytes seguintes
 *   saida = AES(K',X) || AES(K',AES(K',X)) || ...
 *
 * A chave fixa 00..1F NAO e um segredo e nao precisa ser: o df nao existe
 * para esconder nada, existe para MISTURAR. Quem tenta "melhorar" isso
 * usando uma chave secreta esta resolvendo um problema que nao existe e
 * quebrando a compatibilidade com todos os vetores do CAVP.
 *
 * O limite de tamanho abaixo e do buffer, nao da norma. 128 bytes cobrem
 * entropia (32) + nonce (16) + personalizacao (32) com folga larga.
 * ------------------------------------------------------------------ */
#define DF_MAX_ENTRADA  128u

static int block_cipher_df(const uint8_t *entrada, uint32_t n,
                           uint8_t saida[DRBG_SEEDLEN])
{
    /* IV (16) + L (4) + N (4) + entrada + 0x80 + padding */
    uint8_t  s[DRBG_OUTLEN + 8u + DF_MAX_ENTRADA + 1u + DRBG_OUTLEN];
    uint8_t  temp[DRBG_SEEDLEN];
    uint8_t  k_df[DRBG_KEYLEN];
    uint8_t  x[DRBG_OUTLEN];
    uint32_t s_n, i, blocos, contador;
    int      r = 0;

    if (n > DF_MAX_ENTRADA) {
        return -1;
    }

    for (i = 0u; i < DRBG_KEYLEN; i++) {
        k_df[i] = (uint8_t)i;              /* 00 01 02 ... 1F */
    }

    /* Monta IV || S. O IV ocupa o primeiro bloco e e reescrito a cada
     * iteracao; o resto de S nao muda. */
    for (i = 0u; i < DRBG_OUTLEN; i++) {
        s[i] = 0x00u;
    }
    s_n = DRBG_OUTLEN;

    s[s_n++] = (uint8_t)(n >> 24); s[s_n++] = (uint8_t)(n >> 16);
    s[s_n++] = (uint8_t)(n >> 8);  s[s_n++] = (uint8_t)(n);

    s[s_n++] = (uint8_t)(DRBG_SEEDLEN >> 24); s[s_n++] = (uint8_t)(DRBG_SEEDLEN >> 16);
    s[s_n++] = (uint8_t)(DRBG_SEEDLEN >> 8);  s[s_n++] = (uint8_t)(DRBG_SEEDLEN);

    for (i = 0u; i < n; i++) {
        s[s_n++] = entrada[i];
    }
    s[s_n++] = 0x80u;
    while ((s_n % DRBG_OUTLEN) != 0u) {
        s[s_n++] = 0x00u;
    }

    if (aes_chave(k_df) != 0) {
        r = -1;
        goto fim;
    }

    blocos = DRBG_SEEDLEN / DRBG_OUTLEN;      /* 3 */
    for (contador = 0u; contador < blocos; contador++) {
        s[0] = (uint8_t)(contador >> 24); s[1] = (uint8_t)(contador >> 16);
        s[2] = (uint8_t)(contador >> 8);  s[3] = (uint8_t)(contador);
        if (bcc(s, s_n, &temp[contador * DRBG_OUTLEN]) != 0) {
            r = -1;
            goto fim;
        }
    }

    /* K' = temp[0..31], X = temp[32..47] */
    if (aes_chave(temp) != 0) {
        r = -1;
        goto fim;
    }
    for (i = 0u; i < DRBG_OUTLEN; i++) {
        x[i] = temp[DRBG_KEYLEN + i];
    }

    for (i = 0u; i < DRBG_SEEDLEN; i += DRBG_OUTLEN) {
        if (aes_bloco(x, x) != 0) {
            r = -1;
            goto fim;
        }
        for (contador = 0u; contador < DRBG_OUTLEN; contador++) {
            saida[i + contador] = x[contador];
        }
    }

fim:
    wipe(s, sizeof s);
    wipe(temp, sizeof temp);
    wipe(k_df, sizeof k_df);
    wipe(x, sizeof x);
    if (r != 0) {
        wipe(saida, DRBG_SEEDLEN);
    }
    return r;
}

/* Junta ate tres pedacos e passa pelo df. */
static int semente_df(const uint8_t *a, uint32_t a_n,
                      const uint8_t *b, uint32_t b_n,
                      const uint8_t *c, uint32_t c_n,
                      uint8_t saida[DRBG_SEEDLEN])
{
    uint8_t  junto[DF_MAX_ENTRADA];
    uint32_t n = 0u, i;
    int      r;

    if ((a_n + b_n + c_n) > DF_MAX_ENTRADA) {
        return -1;
    }
    for (i = 0u; i < a_n; i++) { junto[n++] = a[i]; }
    for (i = 0u; i < b_n; i++) { junto[n++] = b[i]; }
    for (i = 0u; i < c_n; i++) { junto[n++] = c[i]; }

    r = block_cipher_df(junto, n, saida);
    wipe(junto, sizeof junto);
    return r;
}

/* ------------------------------------------------------------------ */

int drbg_instantiate(drbg_estado_t *st,
                     const uint8_t *entropia, uint32_t entropia_n,
                     const uint8_t *nonce, uint32_t nonce_n,
                     const uint8_t *personalizacao, uint32_t pers_n)
{
    uint8_t  semente[DRBG_SEEDLEN];
    uint32_t i;
    int      r;

    /* Recusar entropia insuficiente e obrigacao, nao zelo: semear com
     * menos do que security_strength produz um DRBG que PARECE forte e
     * nao e, e nada a jusante consegue detectar. */
    if ((entropia == 0) || (entropia_n < DRBG_ENTROPIA_MIN)) {
        return -1;
    }

    if (semente_df(entropia, entropia_n, nonce, nonce_n,
                   personalizacao, pers_n, semente) != 0) {
        return -1;
    }

    for (i = 0u; i < DRBG_KEYLEN; i++) { st->key[i] = 0x00u; }
    for (i = 0u; i < DRBG_OUTLEN; i++) { st->v[i]   = 0x00u; }

    r = ctr_drbg_update(st, semente);
    wipe(semente, sizeof semente);

    if (r != 0) {
        drbg_uninstantiate(st);
        return -1;
    }
    st->reseed_contador = 1u;
    st->instanciado     = 1;
    return 0;
}

int drbg_reseed(drbg_estado_t *st,
                const uint8_t *entropia, uint32_t entropia_n,
                const uint8_t *adicional, uint32_t adicional_n)
{
    uint8_t semente[DRBG_SEEDLEN];
    int     r;

    if (!st->instanciado) {
        return -1;
    }
    if ((entropia == 0) || (entropia_n < DRBG_ENTROPIA_MIN)) {
        return -1;
    }

    if (semente_df(entropia, entropia_n, adicional, adicional_n,
                   0, 0u, semente) != 0) {
        return -1;
    }

    r = ctr_drbg_update(st, semente);
    wipe(semente, sizeof semente);

    if (r != 0) {
        return -1;
    }
    st->reseed_contador = 1u;
    return 0;
}

int drbg_generate(drbg_estado_t *st, uint8_t *saida, uint32_t n,
                  const uint8_t *adicional, uint32_t adicional_n)
{
    uint8_t  extra[DRBG_SEEDLEN];
    uint8_t  bloco[DRBG_OUTLEN];
    uint32_t i, j, resta;
    int      r = 0;

    if (!st->instanciado) {
        return -1;
    }
    if (st->reseed_contador > DRBG_RESEED_INTERVALO) {
        return -2;      /* exige resemeadura, e NAO gera nada */
    }

    for (i = 0u; i < DRBG_SEEDLEN; i++) {
        extra[i] = 0x00u;
    }
    if ((adicional != 0) && (adicional_n != 0u)) {
        if (block_cipher_df(adicional, adicional_n, extra) != 0) {
            r = -1;
            goto fim;
        }
        if (ctr_drbg_update(st, extra) != 0) {
            r = -1;
            goto fim;
        }
    }

    /* A chave do estado tem de estar no CFS: o df acima carregou outra. */
    if (aes_chave(st->key) != 0) {
        r = -1;
        goto fim;
    }

    i = 0u;
    while (i < n) {
        inc_v(st->v);
        if (aes_bloco(st->v, bloco) != 0) {
            r = -1;
            goto fim;
        }
        resta = n - i;
        if (resta > DRBG_OUTLEN) {
            resta = DRBG_OUTLEN;
        }
        for (j = 0u; j < resta; j++) {
            saida[i + j] = bloco[j];
        }
        i += resta;
    }

    /* Update final: e ele que apaga o rastro da saida recem-entregue.
     * Pular isto quando nao ha dado adicional e um erro comum e destroi a
     * resistencia a backtracking -- a norma manda rodar SEMPRE. */
    if (ctr_drbg_update(st, extra) != 0) {
        r = -1;
        goto fim;
    }
    st->reseed_contador++;

fim:
    wipe(extra, sizeof extra);
    wipe(bloco, sizeof bloco);
    if (r != 0) {
        wipe(saida, n);
    }
    return r;
}

void drbg_uninstantiate(drbg_estado_t *st)
{
    wipe(st->key, sizeof st->key);
    wipe(st->v, sizeof st->v);
    st->reseed_contador = 0u;
    st->instanciado     = 0;
}

/* ------------------------------------------------------------------
 * Instancia do dispositivo
 *
 * FRONTEIRA: e o UNICO caminho por onde aleatoriedade sai para o host. A
 * fonte bruta do TRNG nao sai, nunca -- ver hsm_cfs.h.
 * ------------------------------------------------------------------ */
static drbg_estado_t g_drbg;

/* Junta entropia do TRNG. Devolve 0 em sucesso. */
static int colher_entropia(uint8_t *buf, uint32_t n)
{
    uint32_t i;
    for (i = 0u; i < n; i++) {
        if (hsm_trng_byte(&buf[i]) != 0) {
            wipe(buf, n);
            return -1;
        }
    }
    return 0;
}

int drbg_dispositivo_semear(void)
{
    uint8_t entropia[DRBG_ENTROPIA_MIN];
    uint8_t nonce[16];
    uint8_t dna[HSM_DNA_LEN];
    int     r;

    /* O nonce leva o DNA do die. NAO e segredo -- o DNA e legivel por
     * JTAG em qualquer placa -- e nao precisa ser: o nonce existe para
     * separar instancias, nao para esconder. Dois dispositivos com uma
     * fonte igualmente defeituosa ainda divergem por causa dele. */
    if (hsm_cfs_dna(dna) != 0) {
        return -1;
    }
    for (r = 0; r < 8; r++) {
        nonce[r]     = dna[r];
        nonce[8 + r] = (uint8_t)(dna[r] ^ 0xA5u);
    }

    if (colher_entropia(entropia, sizeof entropia) != 0) {
        return -1;
    }

    r = drbg_instantiate(&g_drbg, entropia, sizeof entropia,
                         nonce, sizeof nonce, 0, 0u);
    wipe(entropia, sizeof entropia);
    wipe(nonce, sizeof nonce);
    wipe(dna, sizeof dna);
    return r;
}

int drbg_dispositivo_bytes(uint8_t *saida, uint32_t n)
{
    uint8_t entropia[DRBG_ENTROPIA_MIN];
    int     r;

    r = drbg_generate(&g_drbg, saida, n, 0, 0u);

    if (r == -2) {
        /* Estourou o intervalo: resemeia com entropia nova e refaz. Nao
         * ha caminho que entregue bytes sem resemear -- a politica so vale
         * se nao houver como contorna-la. */
        if (colher_entropia(entropia, sizeof entropia) != 0) {
            return -1;
        }
        r = drbg_reseed(&g_drbg, entropia, sizeof entropia, 0, 0u);
        wipe(entropia, sizeof entropia);
        if (r != 0) {
            return -1;
        }
        r = drbg_generate(&g_drbg, saida, n, 0, 0u);
    }
    return (r == 0) ? 0 : -1;
}
