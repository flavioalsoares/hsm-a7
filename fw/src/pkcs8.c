/* fw/src/pkcs8.c -- chave privada RSA e de curva eliptica em PKCS#8
 *
 * Ver pkcs8.h. Um leitor e um escritor de DER do tamanho exato do que este
 * arquivo precisa: SEQUENCE, INTEGER, OCTET STRING, BIT STRING, OID, NULL e
 * as etiquetas de contexto [0] e [1].
 */
#include "pkcs8.h"
#include "wipe.h"

#define T_INTEGER   0x02u
#define T_BITSTR    0x03u
#define T_OCTETSTR  0x04u
#define T_NULL      0x05u
#define T_OID       0x06u
#define T_SEQUENCE  0x30u
#define T_CTX0      0xA0u
#define T_CTX1      0xA1u

/* Os identificadores, ja com etiqueta e comprimento. Conferidos contra a
 * saida de uma biblioteca independente em host/test_pkcs8.py. */
static const uint8_t ALG_RSA[] = {              /* rsaEncryption, e NULL */
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00
};
static const uint8_t ALG_EC[] = {               /* ecPublicKey, prime256v1 */
    0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};
static const uint8_t OID_P256[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

/* ------------------------------------------------------------------ */
/* Leitor                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *p;
    uint32_t       n;       /* bytes que restam */
} der_t;

/* Le etiqueta e comprimento, e devolve o conteudo em `v`, avancando `d`.
 * Exige a etiqueta `tag` e o comprimento na forma mais curta. */
static int der_le(der_t *d, uint8_t tag, der_t *v)
{
    uint32_t len, nb, i;

    if ((d->n < 2u) || (d->p[0] != tag)) {
        return -1;
    }
    len = d->p[1];
    d->p += 2;
    d->n -= 2u;
    if (len >= 0x80u) {
        nb = len & 0x7Fu;
        if ((nb == 0u) || (nb > 2u) || (d->n < nb)) {
            return -1;                  /* indefinido, ou grande demais */
        }
        len = 0u;
        for (i = 0u; i < nb; i++) {
            len = (len << 8) | d->p[i];
        }
        /* Forma mais curta: 0x81 so de 128 em diante, 0x82 so de 256. */
        if ((len < 0x80u) || ((nb == 2u) && (len < 0x100u))) {
            return -1;
        }
        d->p += nb;
        d->n -= nb;
    }
    if (len > d->n) {
        return -1;
    }
    v->p  = d->p;
    v->n  = len;
    d->p += len;
    d->n -= len;
    return 0;
}

/* 1 se o proximo elemento tem a etiqueta `tag`. */
static int der_e(const der_t *d, uint8_t tag)
{
    return (d->n >= 1u) && (d->p[0] == tag);
}

/* Compara os proximos `n` bytes com `ref` e os consome. */
static int der_fixo(der_t *d, const uint8_t *ref, uint32_t n)
{
    uint32_t i;
    uint8_t  dif = 0u;

    if (d->n < n) {
        return -1;
    }
    for (i = 0u; i < n; i++) {
        dif |= (uint8_t)(d->p[i] ^ ref[i]);
    }
    d->p += n;
    d->n -= n;
    return (dif == 0u) ? 0 : -1;
}

/* INTEGER nao negativo, para `saida` com `tam` bytes, alinhado a direita.
 * Recusa negativo, zero a esquerda sobrando e valor que nao cabe. */
static int der_inteiro(der_t *d, uint8_t *saida, uint32_t tam)
{
    der_t    v;
    uint32_t i;

    if ((der_le(d, T_INTEGER, &v) != 0) || (v.n == 0u)) {
        return -1;
    }
    if ((v.p[0] & 0x80u) != 0u) {
        return -1;                              /* negativo */
    }
    if (v.p[0] == 0x00u) {
        if ((v.n > 1u) && ((v.p[1] & 0x80u) == 0u)) {
            return -1;                          /* zero a esquerda a mais */
        }
        if (v.n > 1u) {
            v.p++;
            v.n--;
        }
    }
    if (v.n > tam) {
        return -1;
    }
    for (i = 0u; i < tam - v.n; i++) {
        saida[i] = 0u;
    }
    for (i = 0u; i < v.n; i++) {
        saida[tam - v.n + i] = v.p[i];
    }
    return 0;
}

/* INTEGER pequeno com um valor exato (as versoes). */
static int der_versao(der_t *d, uint8_t valor)
{
    uint8_t v[1];

    if (der_inteiro(d, v, 1u) != 0) {
        return -1;
    }
    return (v[0] == valor) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Escritor                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  *p;
    uint32_t  n, max;
    uint8_t   estouro;
} esc_t;

static void poe(esc_t *e, uint8_t b)
{
    if (e->n < e->max) {
        e->p[e->n++] = b;
    } else {
        e->estouro = 1u;
    }
}

static void poe_n(esc_t *e, const uint8_t *b, uint32_t n)
{
    uint32_t i;

    for (i = 0u; i < n; i++) {
        poe(e, b[i]);
    }
}

/* Bytes que o campo de comprimento ocupa. */
static uint32_t tam_len(uint32_t len)
{
    return (len < 0x80u) ? 1u : ((len < 0x100u) ? 2u : 3u);
}

static void poe_cab(esc_t *e, uint8_t tag, uint32_t len)
{
    poe(e, tag);
    if (len < 0x80u) {
        poe(e, (uint8_t)len);
    } else if (len < 0x100u) {
        poe(e, 0x81u);
        poe(e, (uint8_t)len);
    } else {
        poe(e, 0x82u);
        poe(e, (uint8_t)(len >> 8));
        poe(e, (uint8_t)len);
    }
}

/* Tamanho do CONTEUDO de um INTEGER com o valor de `v`: sem zeros a
 * esquerda, mais um 00 se o bit alto estiver ligado. */
static uint32_t tam_inteiro(const uint8_t *v, uint32_t n)
{
    uint32_t i = 0u;

    while ((i + 1u < n) && (v[i] == 0u)) {
        i++;
    }
    return (n - i) + (((v[i] & 0x80u) != 0u) ? 1u : 0u);
}

static void poe_inteiro(esc_t *e, const uint8_t *v, uint32_t n)
{
    uint32_t i = 0u;

    while ((i + 1u < n) && (v[i] == 0u)) {
        i++;
    }
    poe_cab(e, T_INTEGER, tam_inteiro(v, n));
    if ((v[i] & 0x80u) != 0u) {
        poe(e, 0x00u);
    }
    poe_n(e, &v[i], n - i);
}

/* Tamanho total de um elemento: etiqueta, comprimento e conteudo. */
static uint32_t tam_tlv(uint32_t conteudo)
{
    return 1u + tam_len(conteudo) + conteudo;
}

/* ------------------------------------------------------------------ */
/* RSA                                                                 */
/* ------------------------------------------------------------------ */

#define MET  128u       /* bytes de um primo de 1024 bits */
#define MOD  256u       /* bytes do modulo */

/* x mod k, com x em bytes e k de ate 24 bits. */
static uint32_t mod_peq(const uint8_t *x, uint32_t n, uint32_t k)
{
    uint32_t i, r = 0u;

    for (i = 0u; i < n; i++) {
        r = ((r << 8) | x[i]) % k;
    }
    return r;
}

/* a^-1 mod m, com m impar pequeno. 0 se nao existe. Euclides estendido. */
static uint32_t inv_peq(uint32_t a, uint32_t m)
{
    int32_t  t = 0, nt = 1, tmp;
    uint32_t r = m, nr = a % m, q, tr;

    while (nr != 0u) {
        q   = r / nr;
        tmp = t - (int32_t)q * nt;  t = nt;  nt = tmp;
        tr  = r - q * nr;           r = nr;  nr = tr;
    }
    if (r != 1u) {
        return 0u;
    }
    return (uint32_t)((t < 0) ? (t + (int32_t)m) : t);
}

/* d = e^-1 mod phi, com phi = (p-1)(q-1) = n - p - q + 1.
 *
 * Sem dividir numero grande por numero grande: com k = -phi^-1 mod e, o
 * numero 1 + k*phi e multiplo de e, e o quociente e d. Como e cabe em 17 a
 * 24 bits, o produto e a divisao sao por numero pequeno.
 *
 * `e` tem de ter no maximo 24 bits: e o que mantem as contas em 32 bits. */
static int rsa_d(const uint8_t n[MOD], const uint8_t p[MET],
                 const uint8_t q[MET], uint32_t e, uint8_t d[MOD])
{
    uint8_t  phi[MOD];
    uint8_t  prod[MOD + 4u];
    uint32_t i, k, inv, resto;
    int32_t  acc, vai;
    uint64_t t;
    int      r = -1;

    if ((e < 3u) || (e > 0xFFFFFFu) || ((e & 1u) == 0u)) {
        return -1;
    }
    /* phi = n - p - q + 1, byte a byte, do menos significativo. */
    vai = 1;
    for (i = 0u; i < MOD; i++) {
        uint32_t j = MOD - 1u - i;
        acc = (int32_t)n[j] + vai;
        if (i < MET) {
            acc -= (int32_t)p[MET - 1u - i];
            acc -= (int32_t)q[MET - 1u - i];
        }
        vai = 0;
        while (acc < 0) {
            acc += 256;
            vai--;
        }
        phi[j] = (uint8_t)acc;
    }
    if (vai != 0) {
        goto fim;                       /* n < p + q - 1: inconsistente */
    }
    inv = inv_peq(mod_peq(phi, MOD, e), e);
    if (inv == 0u) {
        goto fim;                       /* mdc(e, phi) != 1 */
    }
    k = e - inv;                        /* -phi^-1 mod e, de 1 a e-1 */

    /* prod = 1 + k*phi, em MOD + 4 bytes. */
    t = 1u;
    for (i = 0u; i < MOD; i++) {
        t += (uint64_t)k * phi[MOD - 1u - i];
        prod[MOD + 3u - i] = (uint8_t)t;
        t >>= 8;
    }
    for (i = 0u; i < 4u; i++) {
        prod[3u - i] = (uint8_t)t;
        t >>= 8;
    }
    /* d = prod / e. O resto tem de ser zero, e o quociente cabe em MOD
     * bytes porque k < e. */
    resto = 0u;
    for (i = 0u; i < MOD + 4u; i++) {
        uint32_t cur = (resto << 8) | prod[i];
        uint32_t qd  = cur / e;
        resto = cur % e;
        if (i < 4u) {
            if (qd != 0u) {
                goto fim;
            }
        } else {
            d[i - 4u] = (uint8_t)qd;
        }
    }
    r = (resto == 0u) ? 0 : -1;
fim:
    wipe(phi, sizeof phi);
    wipe(prod, sizeof prod);
    if (r != 0) {
        wipe(d, MOD);
    }
    return r;
}

/* 1 se p*q == n. Produto de escola, byte a byte: sao 16 384 produtos de 8
 * bits, uma vez por chave gerada. O PKCS#8 leva n, e um n que nao fosse o
 * produto dos primos do mesmo bloco seria uma chave que nenhum outro
 * sistema conseguiria usar. */
static int rsa_n_confere(const uint8_t n[MOD], const uint8_t p[MET],
                         const uint8_t q[MET])
{
    uint8_t  prod[MOD];
    uint32_t i, j, vai;
    uint8_t  dif = 0u;

    for (i = 0u; i < MOD; i++) {
        prod[i] = 0u;
    }
    for (i = 0u; i < MET; i++) {
        vai = 0u;
        for (j = 0u; j < MET; j++) {
            uint32_t pos = MOD - 1u - i - j;
            uint32_t t = (uint32_t)p[MET - 1u - i] * q[MET - 1u - j]
                       + prod[pos] + vai;
            prod[pos] = (uint8_t)t;
            vai = t >> 8;
        }
        prod[MOD - 1u - i - MET] = (uint8_t)vai;
    }
    for (i = 0u; i < MOD; i++) {
        dif |= (uint8_t)(prod[i] ^ n[i]);
    }
    wipe(prod, sizeof prod);
    return (dif == 0u) ? 1 : 0;
}

int pkcs8_rsa_monta(const uint8_t chave[PKCS8_RSA_INTERNA],
                    const uint8_t n[256],
                    uint8_t *der, uint32_t max, uint32_t *der_n)
{
    static const uint8_t zero[1] = { 0u };
    const uint8_t *e4 = &chave[0];
    const uint8_t *p  = &chave[4];
    const uint8_t *q  = &chave[4u + MET];
    const uint8_t *dp = &chave[4u + 2u * MET];
    const uint8_t *dq = &chave[4u + 3u * MET];
    const uint8_t *qi = &chave[4u + 4u * MET];
    uint8_t  d[MOD];
    uint32_t e, interna, octeto, externa;
    esc_t    w;
    int      r = -1;

    if ((der == 0) || (der_n == 0)) {
        return -1;
    }
    e = ((uint32_t)e4[0] << 24) | ((uint32_t)e4[1] << 16) |
        ((uint32_t)e4[2] << 8) | e4[3];
    if (!rsa_n_confere(n, p, q) || (rsa_d(n, p, q, e, d) != 0)) {
        goto fim;
    }

    interna = tam_tlv(1u)                               /* versao 0 */
            + tam_tlv(tam_inteiro(n, MOD))
            + tam_tlv(tam_inteiro(e4, 4u))
            + tam_tlv(tam_inteiro(d, MOD))
            + tam_tlv(tam_inteiro(p, MET)) + tam_tlv(tam_inteiro(q, MET))
            + tam_tlv(tam_inteiro(dp, MET)) + tam_tlv(tam_inteiro(dq, MET))
            + tam_tlv(tam_inteiro(qi, MET));
    octeto  = tam_tlv(interna);
    externa = tam_tlv(1u) + (uint32_t)sizeof ALG_RSA + tam_tlv(octeto);

    w.p = der;  w.n = 0u;  w.max = max;  w.estouro = 0u;
    poe_cab(&w, T_SEQUENCE, externa);
    poe_inteiro(&w, zero, 1u);
    poe_n(&w, ALG_RSA, (uint32_t)sizeof ALG_RSA);
    poe_cab(&w, T_OCTETSTR, octeto);
    poe_cab(&w, T_SEQUENCE, interna);
    poe_inteiro(&w, zero, 1u);
    poe_inteiro(&w, n, MOD);
    poe_inteiro(&w, e4, 4u);
    poe_inteiro(&w, d, MOD);
    poe_inteiro(&w, p, MET);
    poe_inteiro(&w, q, MET);
    poe_inteiro(&w, dp, MET);
    poe_inteiro(&w, dq, MET);
    poe_inteiro(&w, qi, MET);
    if (w.estouro == 0u) {
        *der_n = w.n;
        r = 0;
    }
fim:
    wipe(d, sizeof d);
    if (r != 0) {
        wipe(der, max);
    }
    return r;
}

int pkcs8_rsa_le(const uint8_t *der, uint32_t der_n,
                 uint8_t chave[PKCS8_RSA_INTERNA])
{
    der_t   topo, ext, oct, rsa;
    uint8_t n[MOD], d[MOD];
    int     r = -1;

    if ((der == 0) || (chave == 0)) {
        return -1;
    }
    topo.p = der;
    topo.n = der_n;
    if ((der_le(&topo, T_SEQUENCE, &ext) != 0) || (topo.n != 0u)) {
        goto fim;
    }
    if ((der_versao(&ext, 0u) != 0) ||
        (der_fixo(&ext, ALG_RSA, (uint32_t)sizeof ALG_RSA) != 0) ||
        (der_le(&ext, T_OCTETSTR, &oct) != 0) || (ext.n != 0u)) {
        goto fim;                       /* inclui atributos: recusados */
    }
    if ((der_le(&oct, T_SEQUENCE, &rsa) != 0) || (oct.n != 0u)) {
        goto fim;
    }
    if ((der_versao(&rsa, 0u) != 0) ||                  /* dois primos */
        (der_inteiro(&rsa, n, MOD) != 0) ||
        (der_inteiro(&rsa, &chave[0], 4u) != 0) ||
        (der_inteiro(&rsa, d, MOD) != 0) ||
        (der_inteiro(&rsa, &chave[4], MET) != 0) ||
        (der_inteiro(&rsa, &chave[4u + MET], MET) != 0) ||
        (der_inteiro(&rsa, &chave[4u + 2u * MET], MET) != 0) ||
        (der_inteiro(&rsa, &chave[4u + 3u * MET], MET) != 0) ||
        (der_inteiro(&rsa, &chave[4u + 4u * MET], MET) != 0) ||
        (rsa.n != 0u)) {
        goto fim;
    }
    /* Modulo de 2048 bits e primos de 1024: e o que rsa.c sabe fazer. E
     * `e` impar e maior que 1. */
    if (((n[0] & 0x80u) == 0u) ||
        ((chave[4] & 0x80u) == 0u) || ((chave[4u + MET] & 0x80u) == 0u) ||
        ((chave[3] & 1u) == 0u) ||
        ((chave[0] | chave[1] | chave[2]) == 0u && chave[3] < 3u)) {
        goto fim;
    }
    r = 0;
fim:
    wipe(n, sizeof n);
    wipe(d, sizeof d);
    if (r != 0) {
        wipe(chave, PKCS8_RSA_INTERNA);
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* Curva P-256                                                         */
/* ------------------------------------------------------------------ */

#define EC_N  32u

int pkcs8_ec_monta(const uint8_t chave[PKCS8_EC_INTERNA],
                   uint8_t *der, uint32_t max, uint32_t *der_n)
{
    static const uint8_t um[1]   = { 1u };
    static const uint8_t zero[1] = { 0u };
    /* BIT STRING: 00 (nenhum bit sobrando), 04 (ponto sem compressao), X, Y */
    const uint32_t bits    = 2u + 2u * EC_N;
    const uint32_t ctx1    = tam_tlv(bits);
    const uint32_t interna = tam_tlv(1u) + tam_tlv(EC_N) + tam_tlv(ctx1);
    const uint32_t octeto  = tam_tlv(interna);
    const uint32_t externa = tam_tlv(1u) + (uint32_t)sizeof ALG_EC
                           + tam_tlv(octeto);
    esc_t w;

    if ((der == 0) || (der_n == 0)) {
        return -1;
    }
    w.p = der;  w.n = 0u;  w.max = max;  w.estouro = 0u;
    poe_cab(&w, T_SEQUENCE, externa);
    poe_inteiro(&w, zero, 1u);
    poe_n(&w, ALG_EC, (uint32_t)sizeof ALG_EC);
    poe_cab(&w, T_OCTETSTR, octeto);
    poe_cab(&w, T_SEQUENCE, interna);
    poe_inteiro(&w, um, 1u);
    poe_cab(&w, T_OCTETSTR, EC_N);
    poe_n(&w, &chave[0], EC_N);
    poe_cab(&w, T_CTX1, ctx1);
    poe_cab(&w, T_BITSTR, bits);
    poe(&w, 0x00u);
    poe(&w, 0x04u);
    poe_n(&w, &chave[EC_N], 2u * EC_N);
    if (w.estouro != 0u) {
        wipe(der, max);
        return -1;
    }
    *der_n = w.n;
    return 0;
}

int pkcs8_ec_le(const uint8_t *der, uint32_t der_n,
                uint8_t chave[PKCS8_EC_INTERNA], int *tem_q)
{
    der_t    topo, ext, oct, ec, v, b;
    uint32_t i;
    int      r = -1;

    if ((der == 0) || (chave == 0) || (tem_q == 0)) {
        return -1;
    }
    *tem_q = 0;
    topo.p = der;
    topo.n = der_n;
    if ((der_le(&topo, T_SEQUENCE, &ext) != 0) || (topo.n != 0u)) {
        goto fim;
    }
    if ((der_versao(&ext, 0u) != 0) ||
        (der_fixo(&ext, ALG_EC, (uint32_t)sizeof ALG_EC) != 0) ||
        (der_le(&ext, T_OCTETSTR, &oct) != 0) || (ext.n != 0u)) {
        goto fim;
    }
    if ((der_le(&oct, T_SEQUENCE, &ec) != 0) || (oct.n != 0u)) {
        goto fim;
    }
    if ((der_versao(&ec, 1u) != 0) ||
        (der_le(&ec, T_OCTETSTR, &v) != 0) || (v.n != EC_N)) {
        goto fim;
    }
    for (i = 0u; i < EC_N; i++) {
        chave[i] = v.p[i];
    }
    for (i = EC_N; i < PKCS8_EC_INTERNA; i++) {
        chave[i] = 0u;
    }
    /* [0] parametros: opcional. Se vier, tem de ser a P-256. */
    if (der_e(&ec, T_CTX0)) {
        if ((der_le(&ec, T_CTX0, &v) != 0) ||
            (der_fixo(&v, OID_P256, (uint32_t)sizeof OID_P256) != 0) ||
            (v.n != 0u)) {
            goto fim;
        }
    }
    /* [1] chave publica: opcional. Ponto sem compressao, 65 bytes. */
    if (der_e(&ec, T_CTX1)) {
        if ((der_le(&ec, T_CTX1, &v) != 0) ||
            (der_le(&v, T_BITSTR, &b) != 0) || (v.n != 0u) ||
            (b.n != 2u + 2u * EC_N) || (b.p[0] != 0x00u) ||
            (b.p[1] != 0x04u)) {
            goto fim;
        }
        for (i = 0u; i < 2u * EC_N; i++) {
            chave[EC_N + i] = b.p[2u + i];
        }
        *tem_q = 1;
    }
    if (ec.n != 0u) {
        goto fim;
    }
    r = 0;
fim:
    if (r != 0) {
        wipe(chave, PKCS8_EC_INTERNA);
        *tem_q = 0;
    }
    return r;
}
