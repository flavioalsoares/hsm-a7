/* fw/src/cmd.c -- enquadramento, CRC e despacho de comandos
 *
 * FRONTEIRA: fora. Este modulo so ve bytes do host. Nenhum handler daqui
 * pode devolver material de chave em claro -- PLANO.md secao 1.
 *
 * O parser de recepcao e a superficie de ataque mais exposta do dispositivo:
 * e o unico codigo que processa entrada arbitraria antes de qualquer
 * verificacao. Por isso ele e deliberadamente burro -- maquina de estados
 * explicita, todos os limites checados, sem alocacao, sem recursao.
 */
/* Sem <string.h> de proposito. O NEORV32 e freestanding e este firmware
 * tambem: nenhuma funcao de libc, todos os lacos explicitos, limpeza pelo
 * wipe() proprio. Menos codigo linkado e menos superficie -- e num HSM
 * "menos coisa que eu nao escrevi" e um objetivo, nao um efeito colateral. */
#include <neorv32.h>

#include "cmd.h"
#include "drbg.h"
#include "dualctl.h"
#include "hsm_cfs.h"
#include "kat.h"
#include "keystore.h"
#include "sha.h"
#include "state.h"
#include "tr31.h"
#include "wipe.h"

/* ------------------------------------------------------------------ */
/* CRC32 (IEEE 802.3 refletido) -- compativel com zlib.crc32           */
/* ------------------------------------------------------------------ */

/* Sem tabela: 1 KB de IMEM vale mais que os ciclos economizados. A 115200
 * baud sobram ~8600 ciclos de 100 MHz por byte recebido; o laco de 8
 * iteracoes cabe com folga de tres ordens de grandeza. */
uint32_t crc32_hsm(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;

    for (uint32_t i = 0u; i < len; i++) {
        crc ^= (uint32_t)data[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    return ~crc;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

/* Assinatura: recebe o payload do pedido, escreve o payload da resposta.
 * out_len entra com o espaco disponivel e sai com o usado. */
typedef hsm_status_t (*cmd_handler_t)(const uint8_t *in, uint16_t in_len,
                                      uint8_t *out, uint16_t *out_len);

static hsm_status_t h_ping(const uint8_t *in, uint16_t in_len,
                           uint8_t *out, uint16_t *out_len)
{
    (void)in;

    /* PING nao leva payload. Recusar payload em vez de ignorar: aceitar
     * lixo silenciosamente esconde erro de enquadramento do host. */
    if (in_len != 0u) {
        *out_len = 0u;
        return STATUS_BAD_PARAM;
    }

    out[0] = 'P';
    out[1] = 'O';
    out[2] = 'N';
    out[3] = 'G';
    *out_len = 4u;

    return STATUS_OK;
}

static hsm_status_t h_get_version(const uint8_t *in, uint16_t in_len,
                                  uint8_t *out, uint16_t *out_len)
{
    (void)in;

    if (in_len != 0u) {
        *out_len = 0u;
        return STATUS_BAD_PARAM;
    }

    /* major, minor, patch, estado atual.
     * O estado vai aqui porque o host precisa saber com o que esta falando
     * antes de mandar qualquer comando sensivel. */
    out[0] = 0u;                        /* major */
    out[1] = 1u;                        /* minor */
    out[2] = 0u;                        /* patch */
    out[3] = (uint8_t)state_get();
    *out_len = 4u;

    return STATUS_OK;
}

static hsm_status_t h_get_dna(const uint8_t *in, uint16_t in_len,
                              uint8_t *out, uint16_t *out_len)
{
    (void)in;

    if (in_len != 0u) {
        *out_len = 0u;
        return STATUS_BAD_PARAM;
    }

    /* Devolve a identidade de fabrica do die: 57 bits em 8 bytes,
     * big-endian, com os 7 bits mais altos em zero.
     *
     * O caminho ate aqui e o registrador DNA do CFS. Nao ha outro: o
     * DNA_PORT e primitiva Xilinx e o XBUS esta desligado por decisao de
     * seguranca (rtl/soc/neorv32_wrapper.vhd).
     *
     * Checklist do CLAUDE.md para comando novo:
     *   estados      todos (ST_NORMAL) -- e identidade, nao operacao
     *   dual control nao
     *   vazamento    nenhum. O DNA e publico: qualquer um com JTAG le o
     *                mesmo valor. Chamar em laco devolve sempre a mesma
     *                constante, entao nao ha oraculo aqui.
     *   exportability nao se aplica -- nao e material de chave, e nunca
     *                pode virar material de chave. Ver hsm_cfs.h.
     *
     * Nao ha caminho de erro que revele o estado interno: se o hardware
     * nao terminou a leitura, sai INTERNAL_ERROR sem payload. */
    if (hsm_cfs_dna(out) != 0) {
        *out_len = 0u;
        return STATUS_INTERNAL_ERROR;
    }

    *out_len = HSM_DNA_LEN;
    return STATUS_OK;
}


/* ==================================================================== */
/* Fase 2 -- primitivas                                                 */
/*                                                                      */
/* LEIA cmd.h antes de mexer aqui. AES e HMAC recebem a chave no payload */
/* e por isso rodam SO em UNINITIALIZED: no instante em que existir uma  */
/* LMK, a mascara de estados os desliga. Um comando que aceita chave em  */
/* claro nao pode coexistir com chave de verdade no mesmo dispositivo.   */
/* ==================================================================== */

/* AES-256 ECB, um bloco.
 *
 * Checklist do CLAUDE.md:
 *   estados      SO ST_UNINIT -- ver acima
 *   dual control nao (nao ha chave do dispositivo envolvida)
 *   vazamento    em laco com entradas escolhidas, e um oraculo de AES para
 *                uma chave que o CHAMADOR ja possui: ele escolheu. Nao ha
 *                nada aqui que ele nao pudesse calcular sozinho.
 *   exportability nao se aplica -- nao ha slot
 *   log          fase 3, junto com o key store
 *
 * ECB de um bloco so, de proposito. Encadeamento e do host, mesma divisao
 * dos testbenches de KAT: modo de operacao em RTL custa fabric e esconde
 * erro de padding onde depurar exige simulacao.
 */
static hsm_status_t h_aes(const uint8_t *in, uint16_t in_len,
                          uint8_t *out, uint16_t *out_len, int cifra)
{
    hsm_status_t st = STATUS_OK;

    *out_len = 0u;

    if (in_len != (HSM_AES_KEY_LEN + HSM_AES_BLOCK_LEN)) {
        return STATUS_BAD_PARAM;
    }

    if (hsm_cfs_aes_key(in) != 0) {
        st = STATUS_INTERNAL_ERROR;
    } else if (hsm_cfs_aes_block(&in[HSM_AES_KEY_LEN], out, cifra) != 0) {
        st = STATUS_INTERNAL_ERROR;
    } else {
        *out_len = HSM_AES_BLOCK_LEN;
    }

    /* A chave expandida fica no aes_key_mem depois da operacao. Apagar
     * agora, e nao "na proxima vez que alguem carregar chave": material de
     * chave nao espera pelo proximo comando. */
    (void)hsm_cfs_wipe();

    if (st != STATUS_OK) {
        wipe(out, HSM_AES_BLOCK_LEN);
    }
    return st;
}

static hsm_status_t h_aes_enc(const uint8_t *in, uint16_t in_len,
                              uint8_t *out, uint16_t *out_len)
{
    return h_aes(in, in_len, out, out_len, 1);
}

static hsm_status_t h_aes_dec(const uint8_t *in, uint16_t in_len,
                              uint8_t *out, uint16_t *out_len)
{
    return h_aes(in, in_len, out, out_len, 0);
}

/* SHA-256 de mensagem inteira.
 *
 * Checklist:
 *   estados      ST_NORMAL -- hash publico, sem chave, nao ha o que vazar
 *   dual control nao
 *   vazamento    nenhum: SHA-256 e funcao publica. Em laco o chamador so
 *                obtem o que qualquer biblioteca daria.
 */
static hsm_status_t h_sha256(const uint8_t *in, uint16_t in_len,
                             uint8_t *out, uint16_t *out_len)
{
    *out_len = 0u;

    if (hsm_sha256(in, in_len, out) != 0) {
        return STATUS_INTERNAL_ERROR;
    }
    *out_len = HSM_SHA256_LEN;
    return STATUS_OK;
}

/* HMAC-SHA-256.
 *
 * Payload: klen(1) || chave(klen) || mensagem
 *
 * Checklist:
 *   estados      SO ST_UNINIT -- recebe chave em claro
 *   vazamento    oraculo de HMAC sob chave escolhida pelo chamador
 */
static hsm_status_t h_hmac(const uint8_t *in, uint16_t in_len,
                           uint8_t *out, uint16_t *out_len)
{
    uint16_t klen;

    *out_len = 0u;

    if (in_len < 1u) {
        return STATUS_BAD_PARAM;
    }
    klen = in[0];
    if ((uint32_t)klen + 1u > (uint32_t)in_len) {
        return STATUS_BAD_PARAM;
    }

    if (hsm_hmac_sha256(&in[1], klen,
                        &in[1u + klen], (uint16_t)(in_len - 1u - klen),
                        out) != 0) {
        return STATUS_INTERNAL_ERROR;
    }
    *out_len = HSM_SHA256_LEN;
    return STATUS_OK;
}

/* RANDOM -- saida do CTR_DRBG.
 *
 * Payload: n em 2 bytes big-endian.
 *
 * Checklist:
 *   estados      ST_NORMAL
 *   dual control nao
 *   vazamento    NENHUM sobre o estado do DRBG. E o ponto do update apos
 *                cada geracao (SP 800-90A): quem capturar o estado depois
 *                nao reconstroi o que ja saiu. Chamar em laco consome o
 *                intervalo de resemeadura, e a resemeadura acontece
 *                sozinha -- nao ha caminho que entregue bytes sem ela.
 *   fronteira    devolve saida do DRBG. A amostra BRUTA da fonte NUNCA sai
 *                daqui, em nenhum comando. Ver hsm_cfs.h.
 */
static hsm_status_t h_random(const uint8_t *in, uint16_t in_len,
                             uint8_t *out, uint16_t *out_len)
{
    uint32_t n;

    *out_len = 0u;

    if (in_len != 2u) {
        return STATUS_BAD_PARAM;
    }
    n = ((uint32_t)in[0] << 8) | (uint32_t)in[1];
    if ((n == 0u) || (n > CMD_RANDOM_MAX)) {
        return STATUS_BAD_PARAM;
    }

    if (drbg_dispositivo_bytes(out, n) != 0) {
        wipe(out, n);
        return STATUS_INTERNAL_ERROR;
    }
    *out_len = (uint16_t)n;
    return STATUS_OK;
}

/* SELFTEST -- reroda o POST e devolve a mascara de falhas.
 *
 * Checklist:
 *   estados      ST_NORMAL **e** ST_TAMPERED. E a unica excecao ao "um
 *                dispositivo comprometido responde o minimo possivel", e
 *                ela e deliberada: sem isto, um dispositivo que reprovou
 *                no boot fica mudo sobre O QUE reprovou, e o operador nao
 *                tem nada alem de um LED vermelho.
 *   dual control nao
 *   vazamento    revela QUAL primitiva falhou. E informacao de
 *                diagnostico, nao material de chave, e o valor dela para
 *                quem opera supera o valor para quem ataca -- um atacante
 *                que ja consegue derrubar uma primitiva nao precisa que a
 *                gente confirme.
 *
 * Reprovar aqui leva a TAMPERED, igual ao boot. Um dispositivo que passa
 * no boot e falha depois esta pior, nao melhor.
 */
static hsm_status_t h_selftest(const uint8_t *in, uint16_t in_len,
                               uint8_t *out, uint16_t *out_len)
{
    unsigned r;

    (void)in;
    *out_len = 0u;

    if (in_len != 0u) {
        return STATUS_BAD_PARAM;
    }

    r = kat_post();
    out[0]   = (uint8_t)r;
    *out_len = 1u;

    /* ⚠ O AUTOTESTE E DESTRUTIVO, E ISSO NAO PODE FICAR IMPLICITO.
     *
     * O teste de funcao critica do key store INSTALA e APAGA chaves de
     * teste, e termina zerando o store inteiro -- LMK inclusive. Entao
     * rodar SELFTEST num dispositivo carregado APAGA a chave mestra.
     *
     * Isso ja era verdade antes desta linha existir, e sem ela o
     * dispositivo continuava dizendo OPERATIONAL com o key store vazio:
     * estado e realidade divergindo, que e a pior coisa que uma maquina de
     * estados pode fazer. O operador rodava um diagnostico e o dispositivo
     * mentia sobre ter chave.
     *
     * A escolha aqui e tornar a destruicao VISIVEL, nao evita-la: o
     * autoteste tem de exercitar o key store de verdade para valer alguma
     * coisa, e um autoteste que poupasse a LMK testaria um caminho que
     * nao e o que roda no boot.
     *
     * De TAMPERED nao se sai -- state_set() e absorvente. */
    (void)keystore_zeroiza_tudo();
    state_set(HSM_UNINITIALIZED);

    if (r != KAT_OK) {
        state_set(HSM_TAMPERED);
        return STATUS_SELFTEST_FAIL;
    }
    return STATUS_OK;
}

/* ZEROIZE -- apaga toda chave, e prova.
 *
 * Payload: vazio. Resposta: estado_atual(1).
 *
 * Checklist:
 *   estados      TODOS, TAMPERED inclusive. E o unico comando com essa
 *                mascara, e a razao e simples: um dispositivo que nao se
 *                deixa apagar nao garante nada alem de que a chave
 *                continua la. Em TAMPERED e ainda mais necessario -- e
 *                exatamente quando se quer apagar.
 *
 *   dual control SIM. E destrutivo e irreversivel, e a exigencia e a mesma
 *                de carregar a LMK: quem pode criar a chave mestra e quem
 *                pode destrui-la.
 *
 *                ⚠ A ASSIMETRIA COM O GATILHO AUTOMATICO E O PONTO. O
 *                autoteste reprovado apaga sem pedir autorizacao a
 *                ninguem. Pessoas precisam de duas pessoas; o dispositivo
 *                que se descobre comprometido nao precisa de ninguem. Se
 *                o gatilho automatico exigisse dual control, bastaria nao
 *                haver operador na sala para a chave sobreviver ao
 *                comprometimento.
 *
 *   vazamento    nada -- ele destroi. Em laco e negacao de servico, e o
 *                dual control ja cobre isso: a recusa NAO gasta o rearme,
 *                entao um host hostil nao consegue nem apagar nem impedir
 *                a cerimonia.
 *
 *   exportability nao se aplica, e vale dizer por que em vez de deixar em
 *                branco: `exportabilidade='N'` protege contra a chave
 *                SAIR, nao contra ser APAGADA. Uma chave que o
 *                dispositivo nao pudesse apagar seria uma chave que ele
 *                nao controla.
 *
 *   log          TODO -- fw/src/audit_log.c ainda e um placeholder. Este e
 *                o comando que mais precisa de registro, e ele ainda nao
 *                existe. Fica anotado aqui e em doc/fase3-notas.md.
 */
static hsm_status_t h_zeroize(const uint8_t *in, uint16_t in_len,
                              uint8_t *out, uint16_t *out_len)
{
    (void)in;
    *out_len = 0u;

    if (in_len != 0u) {
        return STATUS_BAD_PARAM;
    }

    if (!dualctl_autoriza()) {
        return STATUS_NOT_AUTHORIZED;
    }

    /* Apaga e CONFERE. A ordem importa: o estado so desce depois de a
     * prova passar. Descer para UNINITIALIZED com material vivo na BRAM
     * seria anunciar "nao ha chave aqui" sobre uma chave que ficou. */
    if (keystore_zeroiza_tudo() != 0) {
        /* Apagou e nao conseguiu provar. O dispositivo nao tem como saber
         * o que sobrou, entao assume o pior sobre si mesmo -- e essa e a
         * unica transicao para TAMPERED que um comando provoca. */
        state_set(HSM_TAMPERED);
        out[0]   = (uint8_t)state_get();
        *out_len = 1u;
        return STATUS_INTERNAL_ERROR;
    }

    /* Absorvente: se ja estava em TAMPERED, continua. A chave foi embora
     * de qualquer jeito, que era o pedido. */
    state_set(HSM_UNINITIALIZED);

    out[0]   = (uint8_t)state_get();
    *out_len = 1u;
    return STATUS_OK;
}

/* ==================================================================== */
/* Fase 3 -- cerimonia de LMK                                           */
/*                                                                      */
/* Aqui o dispositivo passa a GUARDAR chave, e a diferenca em relacao a  */
/* fase 2 e visivel na assinatura dos comandos: nada do que entra sai de */
/* volta. Entram componentes, sai KCV.                                   */
/* ==================================================================== */

/* LMK_LOAD_COMPONENT -- um componente da chave mestra.
 *
 * Payload: n(1) || componente(32)
 * Resposta: kcv_do_componente(3) || carregados(1) || estado(1)
 *
 * Checklist do CLAUDE.md:
 *
 *   estados      SO ST_UNINIT. Uma LMK so se carrega em dispositivo sem
 *                LMK. Depois do terceiro componente o estado vira
 *                AUTHORIZED e este comando se desliga sozinho, pela
 *                mascara -- nao ha caminho para trocar a chave mestra por
 *                cima da existente, o que seria substituir chave sem
 *                apagar as derivadas dela.
 *
 *   dual control SIM. E o unico comando da fase que exige presenca fisica,
 *                e o motivo e que ele e o unico que CRIA a raiz. Ver
 *                dualctl.h para o que este mecanismo prova e o que nao
 *                prova.
 *
 *   vazamento    em laco com entradas escolhidas, devolve o KCV de
 *                componentes que o proprio chamador escolheu -- que ele
 *                calcularia sozinho com qualquer biblioteca de AES. Sobre
 *                a LMK acumulada nao devolve nada: o KCV que sai aqui e do
 *                COMPONENTE, nunca do acumulado.
 *
 *                O caminho que merece atencao e outro: quem carregar os
 *                componentes 1 e 2 sabendo o 0 obtem, pelo LMK_STATUS, um
 *                oraculo de 3 bytes sobre a LMK inteira. Sao 3 bytes --
 *                sobram 2^232 candidatos, e nao ha ataque. Mas e por essa
 *                razao que uma cerimonia de verdade tem todos os
 *                custodiantes presentes o tempo todo, e nao um de cada vez.
 *
 *   exportability nao se aplica -- a LMK nao tem slot e nao e exportavel
 *                por caminho nenhum (keystore.h).
 *
 *   log          fase 3, junto com audit_log.c. Este e o primeiro comando
 *                do projeto que PRECISA de trilha: quem carregou qual
 *                componente e quando.
 *
 * A honestidade que falta: num HSM de verdade o componente entra por
 * teclado local ou smart card, e nao pela mesma porta serial por onde o
 * host fala. Aqui a porta e uma so, entao o componente atravessa o link do
 * host em claro. E a maior distancia entre este projeto e o modelo -- e
 * esta escrita aqui, e nao escondida.
 */
static hsm_status_t h_lmk_load_component(const uint8_t *in, uint16_t in_len,
                                         uint8_t *out, uint16_t *out_len)
{
    uint8_t kcv[KS_KCV_LEN];
    uint8_t n;

    *out_len = 0u;

    if (in_len != (uint16_t)(1u + KS_KEY_MAX)) {
        return STATUS_BAD_PARAM;
    }
    n = in[0];

    /* Valida ANTES de consumir a autorizacao. Um erro de indice do host nao
     * pode custar um aperto de botao ao operador -- se custasse, cada
     * tentativa malfeita exigiria repetir o gesto, e a cerimonia viraria
     * um jogo de paciencia. */
    if ((n >= KS_LMK_N_COMPONENTES) || (n != lmk_componentes_carregados())) {
        return STATUS_BAD_PARAM;
    }

    if (!dualctl_autoriza()) {
        return STATUS_NOT_AUTHORIZED;
    }

    /* KCV do componente, para o custodiante conferir que digitou o dele e
     * nao o do vizinho. E o unico jeito de errar e descobrir na hora: sem
     * isso, um componente trocado so aparece no KCV final, quando ja nao
     * da para saber qual dos tres estava errado. */
    if (keystore_kcv(&in[1], KS_KEY_MAX, kcv) != 0) {
        return STATUS_INTERNAL_ERROR;
    }

    if (lmk_componente(n, &in[1]) != 0) {
        wipe(kcv, sizeof kcv);
        return STATUS_INTERNAL_ERROR;
    }

    /* Terceiro componente: a raiz existe. O estado muda AQUI e nao por
     * comando separado -- "tenho LMK" e "estou em AUTHORIZED" tem de ser a
     * mesma afirmacao, ou o estado passa a ser uma opiniao. */
    if (lmk_completa()) {
        state_set(HSM_AUTHORIZED);
    }

    out[0] = kcv[0];
    out[1] = kcv[1];
    out[2] = kcv[2];
    out[3] = lmk_componentes_carregados();
    out[4] = (uint8_t)state_get();
    *out_len = 5u;

    wipe(kcv, sizeof kcv);
    return STATUS_OK;
}

/* LMK_STATUS -- quantos componentes entraram, e o KCV se estiver completa.
 *
 * Checklist:
 *   estados      ST_NORMAL. E o comando que o operador usa para conferir a
 *                cerimonia, e ele precisa funcionar antes, durante e
 *                depois.
 *   dual control nao. Nao muda nada.
 *   vazamento    3 bytes derivados da LMK, e so quando ela esta completa.
 *                E o unico dado derivado dela que atravessa a fronteira,
 *                por decisao explicita (keystore.h): sem KCV o operador
 *                nao tem como saber se carregou a chave certa, e com 3
 *                bytes ninguem recupera 256 bits.
 *   exportability nao se aplica.
 *
 * Comprimento FIXO, com o KCV zerado enquanto a LMK esta incompleta. Uma
 * resposta que encolhe quando nao ha KCV anunciaria o mesmo fato pelo
 * tamanho do frame -- aqui isso nao seria segredo nenhum, mas o habito de
 * nao deixar o comprimento falar e barato de manter e caro de adquirir
 * depois.
 */
static hsm_status_t h_lmk_status(const uint8_t *in, uint16_t in_len,
                                 uint8_t *out, uint16_t *out_len)
{
    uint8_t i;

    (void)in;
    *out_len = 0u;

    if (in_len != 0u) {
        return STATUS_BAD_PARAM;
    }

    out[0] = lmk_componentes_carregados();
    out[1] = (uint8_t)lmk_completa();

    for (i = 0u; i < KS_KCV_LEN; i++) {
        out[2u + i] = 0x00u;
    }
    if (lmk_completa()) {
        if (lmk_kcv(&out[2]) != 0) {
            wipe(out, 2u + KS_KCV_LEN);
            return STATUS_INTERNAL_ERROR;
        }
    }

    *out_len = (uint16_t)(2u + KS_KCV_LEN);
    return STATUS_OK;
}

/* SET_STATE -- ativa o dispositivo depois da cerimonia.
 *
 * Payload: estado_alvo(1). Resposta: estado_atual(1).
 *
 * Checklist:
 *   estados      SO ST_AUTH, e o unico alvo aceito e OPERATIONAL.
 *
 *                Nao ha caminho de volta por aqui. Voltar a UNINITIALIZED
 *                e trabalho do ZEROIZE, que APAGA -- um SET_STATE capaz de
 *                "desinicializar" deixaria a LMK viva com o estado
 *                dizendo que nao ha chave, e o estado deixaria de ser
 *                verdade sobre o dispositivo. Entrar em TAMPERED por
 *                comando tambem nao: TAMPERED e um veredito do
 *                dispositivo sobre si mesmo.
 *
 *   dual control SIM. Ativar e o momento em que o dispositivo passa a
 *                atender operacao com chave real; e uma decisao de
 *                cerimonia, nao de host.
 *
 *   vazamento    devolve o proprio estado, que o GET_VERSION ja da.
 *   exportability nao se aplica.
 *
 * O efeito colateral que interessa e o que DESAPARECE: em OPERATIONAL, os
 * comandos da fase 2 que recebem chave em claro (AES_ENC, AES_DEC, HMAC)
 * param de responder, porque a mascara deles e ST_UNINIT. Nao ha linha de
 * codigo desligando nada -- a tabela e que nao os permite mais.
 */
static hsm_status_t h_set_state(const uint8_t *in, uint16_t in_len,
                                uint8_t *out, uint16_t *out_len)
{
    *out_len = 0u;

    if (in_len != 1u) {
        return STATUS_BAD_PARAM;
    }
    if (in[0] != (uint8_t)HSM_OPERATIONAL) {
        return STATUS_BAD_PARAM;
    }

    /* Defesa em profundidade: a mascara ja garante AUTHORIZED, e AUTHORIZED
     * so se alcanca com a LMK completa. Conferir de novo custa uma
     * comparacao e cobre o caso em que alguem, um dia, acrescente outro
     * caminho para AUTHORIZED sem perceber o que ele implica. */
    if (!lmk_completa()) {
        return STATUS_WRONG_STATE;
    }

    if (!dualctl_autoriza()) {
        return STATUS_NOT_AUTHORIZED;
    }

    state_set(HSM_OPERATIONAL);

    out[0]   = (uint8_t)state_get();
    *out_len = 1u;
    return STATUS_OK;
}

/* ==================================================================== */
/* Fase 3 -- comandos de chave                                          */
/*                                                                      */
/* Os quatro tem a MESMA mascara (ST_OPER) e NENHUM exige dual control.  */
/*                                                                      */
/* Vale dizer por que, porque a intuicao puxa para o lado errado: dual   */
/* control e para CERIMONIA, nao para operacao. Carregar a chave mestra  */
/* e ativar o dispositivo sao eventos raros, com gente na frente da      */
/* placa. Gerar, exportar e importar chave e o que um HSM faz o dia      */
/* inteiro -- exigir dois dedos ali nao aumentaria seguranca nenhuma, so */
/* garantiria que ninguem usa o equipamento, e um controle que impede o  */
/* uso legitimo e desligado no primeiro dia ruim.                        */
/*                                                                      */
/* O que protege estes comandos e outra coisa, e ela e estrutural: a     */
/* chave nunca sai em claro, o key block e autenticado sobre cabecalho   */
/* MAIS corpo, e `exportabilidade` decide quem pode sair.                */
/* ==================================================================== */

/* GEN_KEY -- gera chave dentro da fronteira.
 *
 * Payload: uso(2) || algoritmo(1) || modo(1) || exportabilidade(1).
 * Resposta: handle(1) || kcv(3).
 *
 * Checklist:
 *   estados      ST_OPER. Antes disso nao ha LMK, e uma chave que nao
 *                pode ser embrulhada e uma chave que morre no
 *                desligamento sem ter servido para nada.
 *   dual control nao -- ver o bloco acima.
 *   vazamento    o KCV, tres bytes, por chave gerada. E oraculo de
 *                verificacao, nao de recuperacao: 1 em 16 milhoes de
 *                colisao basta para pegar erro de digitacao e nao basta
 *                para atacar. Em laco, esgota os 16 slots -- negacao de
 *                servico, respondida com STATUS_NO_SLOT, e o operador
 *                apaga o que nao usa.
 *   exportability o host ESCOLHE aqui, e e legitimo: o ponto nao e
 *                impedir que se peca 'E', e que uma vez marcada 'N' a
 *                chave nao saia por caminho nenhum.
 *   log          TODO -- audit_log.c ainda e placeholder.
 *
 * O CONTRASTE COM A FASE 2 e o que este comando ensina. `AES_ENC` recebia
 * a chave no payload; aqui o host escolhe os METADADOS e nunca ve o
 * material. Os dois comandos nao podem coexistir com chave de verdade no
 * dispositivo, e nao coexistem: a mascara de `AES_ENC` e ST_UNINIT.
 */
static hsm_status_t h_gen_key(const uint8_t *in, uint16_t in_len,
                              uint8_t *out, uint16_t *out_len)
{
    uint8_t      chave[KS_KEY_MAX];
    ks_handle_t  h;
    ks_info_t    info;
    hsm_status_t r = STATUS_INTERNAL_ERROR;
    uint8_t      k;

    *out_len = 0u;

    if (in_len != 5u) {
        return STATUS_BAD_PARAM;
    }

    /* Do CTR_DRBG do dispositivo, semeado por uma fonte que passou nos
     * health tests -- nao do host, e nao de `rand()`. Uma chave gerada
     * fora da fronteira nao e uma chave do dispositivo. */
    if (drbg_dispositivo_bytes(chave, KS_KEY_MAX) != 0) {
        goto fim;
    }

    h = keystore_instala(&in[0], in[2], in[3], in[4], chave, KS_KEY_MAX);
    if (h == KS_HANDLE_INVALIDO) {
        /* Duas causas, e o host merece distingui-las: cabecalho invalido
         * (erro dele) e store cheio (estado do dispositivo). Nenhuma das
         * duas e segredo -- o KEY_INFO ja permite contar slots ocupados
         * --, entao separar ajuda o operador sem dar nada a ninguem. */
        r = (keystore_livres() == 0u) ? STATUS_NO_SLOT : STATUS_BAD_PARAM;
        goto fim;
    }

    if (keystore_info(h, &info) != 0) {
        goto fim;
    }

    out[0] = (uint8_t)h;
    for (k = 0u; k < KS_KCV_LEN; k++) {
        out[1u + k] = info.kcv[k];
    }
    *out_len = 1u + KS_KCV_LEN;
    r = STATUS_OK;

fim:
    /* A chave ja esta no slot; esta copia nao pode sobreviver ao handler.
     * `keystore_instala` copia, nao toma posse. */
    wipe(chave, sizeof chave);
    return r;
}

/* EXPORT_KEY -- a chave sai, embrulhada.
 *
 * Payload: handle(1). Resposta: key block X9.143 em ASCII.
 *
 * Checklist:
 *   estados      ST_OPER -- precisa da LMK para derivar KBEK/KBAK.
 *   dual control nao. O que torna a exportacao segura nao e uma pessoa:
 *                e o embrulho. O host recebe bytes que nao sabe abrir.
 *   vazamento    o mesmo slot exportado duas vezes da blocos DIFERENTES,
 *                porque o enchimento e aleatorio. Isso nao e desperdicio
 *                -- e o que impede um observador de saber que duas
 *                exportacoes carregam a mesma chave.
 *   exportability SIM, e este e O comando onde ela decide.
 *                `keystore_exporta()` e o unico caminho para os bytes, e
 *                recusa 'N'. Um slot 'N' devolve STATUS_NOT_EXPORTABLE.
 *   log          TODO.
 *
 * A LMK NAO aparece aqui. `lmk_deriva_kb()` devolve as duas subchaves
 * derivadas por CMAC; a chave mestra nao sai de keystore.c. Se este
 * handler precisasse dela, existiria um `lmk_exporta()` -- e a promessa
 * "a LMK nao sai" viraria convencao.
 */
static hsm_status_t h_export_key(const uint8_t *in, uint16_t in_len,
                                 uint8_t *out, uint16_t *out_len)
{
    uint8_t      kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t      chave[KS_KEY_MAX];
    uint8_t      enchimento[TR31_BLOCO];
    ks_info_t    info;
    tr31_cab_t   cab;
    uint32_t     n = 0u;
    uint8_t      klen;
    hsm_status_t r = STATUS_INTERNAL_ERROR;

    *out_len = 0u;

    if (in_len != 1u) {
        return STATUS_BAD_PARAM;
    }
    if (keystore_info(in[0], &info) != 0) {
        return STATUS_BAD_PARAM;          /* handle invalido ou slot vazio */
    }

    klen = keystore_exporta(in[0], chave);
    if (klen == 0u) {
        return STATUS_NOT_EXPORTABLE;
    }

    /* Enchimento do corpo. Vem do DRBG e nao de dentro do tr31.c: uma
     * funcao de formato que puxa entropia por conta propria e impossivel
     * de testar de forma deterministica. */
    if (drbg_dispositivo_bytes(enchimento, sizeof enchimento) != 0) {
        goto fim;
    }
    if (lmk_deriva_kb(kbek, kbak) != 0) {
        goto fim;
    }

    /* Os campos do cabecalho vem do SLOT, nao do pedido. E o que faz o
     * bloco carregar a politica junto com a chave: quem importar recebe
     * `exportabilidade` e `modo` como estavam aqui, autenticados. */
    cab.uso[0]          = info.uso[0];
    cab.uso[1]          = info.uso[1];
    cab.algoritmo       = info.algoritmo;
    cab.modo            = info.modo;
    cab.versao_chave[0] = (uint8_t)'0';
    cab.versao_chave[1] = (uint8_t)'0';
    cab.exportabilidade = info.exportabilidade;

    if (tr31_embrulha(kbek, kbak, &cab, chave, klen,
                      enchimento, (uint8_t)sizeof enchimento,
                      (char *)out, &n) != 0) {
        goto fim;
    }

    *out_len = (uint16_t)n;
    r = STATUS_OK;

fim:
    wipe(chave, sizeof chave);
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    wipe(enchimento, sizeof enchimento);
    if (r != STATUS_OK) {
        wipe(out, CMD_MAX_PAYLOAD);
    }
    return r;
}

/* IMPORT_KEY -- a chave volta, e so se o MAC fechar.
 *
 * Payload: key block em ASCII. Resposta: handle(1) || kcv(3).
 *
 * Checklist:
 *   estados      ST_OPER.
 *   dual control nao.
 *   vazamento    E O COMANDO MAIS EXPOSTO DOS QUATRO. Um atacante manda
 *                blocos forjados em laco, e cada resposta e informacao.
 *                Por isso TODA recusa devolve STATUS_BAD_PARAM: bloco
 *                malformado, hexadecimal invalido, MAC errado e
 *                comprimento de chave impossivel sao o MESMO codigo.
 *                Distinguir em qual etapa parou e o oraculo de padding
 *                classico -- o atacante nao precisa da chave, precisa so
 *                que a vitima diga onde a validacao falhou.
 *   exportability vem DO BLOCO, autenticada pelo MAC. E por isso que o
 *                cabecalho X9.143 entra no MAC: sem isso, alterar um
 *                caractere 'N' para 'E' promoveria a chave na importacao.
 *   log          TODO.
 *
 * ⚠ Um bloco com chave de 128 ou 192 bits e RECUSADO, e nao por
 * descuido: o key store so guarda AES-256 (`keystore_instala` exige
 * KS_KEY_MAX). Aceitar e guardar truncado seria pior que recusar.
 */
static hsm_status_t h_import_key(const uint8_t *in, uint16_t in_len,
                                 uint8_t *out, uint16_t *out_len)
{
    uint8_t      kbek[KS_KEY_MAX], kbak[KS_KEY_MAX];
    uint8_t      chave[TR31_CHAVE_MAX];
    uint8_t      klen = 0u;
    tr31_cab_t   cab;
    ks_handle_t  h;
    ks_info_t    info;
    hsm_status_t r = STATUS_INTERNAL_ERROR;
    uint8_t      k;

    *out_len = 0u;

    if ((in_len < TR31_CAB_LEN) || (in_len > TR31_ASCII_MAX)) {
        return STATUS_BAD_PARAM;
    }
    if (lmk_deriva_kb(kbek, kbak) != 0) {
        goto fim;
    }

    if (tr31_desembrulha(kbek, kbak, (const char *)in, (uint32_t)in_len,
                         &cab, chave, &klen) != 0) {
        r = STATUS_BAD_PARAM;             /* UM codigo para toda recusa */
        goto fim;
    }

    h = keystore_instala(cab.uso, cab.algoritmo, cab.modo,
                         cab.exportabilidade, chave, klen);
    if (h == KS_HANDLE_INVALIDO) {
        r = (keystore_livres() == 0u) ? STATUS_NO_SLOT : STATUS_BAD_PARAM;
        goto fim;
    }
    if (keystore_info(h, &info) != 0) {
        goto fim;
    }

    out[0] = (uint8_t)h;
    for (k = 0u; k < KS_KCV_LEN; k++) {
        out[1u + k] = info.kcv[k];
    }
    *out_len = 1u + KS_KCV_LEN;
    r = STATUS_OK;

fim:
    wipe(chave, sizeof chave);
    wipe(kbek, sizeof kbek);
    wipe(kbak, sizeof kbak);
    return r;
}

/* KEY_INFO -- metadados, e nunca chave.
 *
 * Payload: handle(1).
 * Resposta: uso(2)||alg(1)||modo(1)||exp(1)||key_len(1)||kcv(3)||usos(4).
 *
 * Checklist:
 *   estados      ST_OPER.
 *   dual control nao.
 *   vazamento    ocupacao dos slots e o KCV de chaves que o chamador
 *                talvez nao tenha criado. E deliberado e limitado: sem
 *                isto o operador nao tem inventario, e tres bytes de KCV
 *                nao recuperam 256 bits. O que NAO sai e o material --
 *                nao existe "me devolva o slot inteiro", e o tipo que
 *                contem chave nem aparece no header do key store.
 *   exportability nao se aplica: nada de chave atravessa aqui.
 *   log          TODO.
 *
 * O contador de uso vai junto porque e o dado que revela padrao de uso
 * sem revelar uso nenhum -- uma chave de dados com contador zerado num
 * dispositivo em producao e um sintoma, nao uma estatistica.
 */
static hsm_status_t h_key_info(const uint8_t *in, uint16_t in_len,
                               uint8_t *out, uint16_t *out_len)
{
    ks_info_t info;
    uint8_t   k;

    *out_len = 0u;

    if (in_len != 1u) {
        return STATUS_BAD_PARAM;
    }
    if (keystore_info(in[0], &info) != 0) {
        /* Handle invalido e slot vazio devolvem o MESMO codigo: separar
         * permitiria mapear o key store sem instalar nada. */
        return STATUS_BAD_PARAM;
    }

    out[0]  = info.uso[0];
    out[1]  = info.uso[1];
    out[2]  = info.algoritmo;
    out[3]  = info.modo;
    out[4]  = info.exportabilidade;
    out[5]  = info.key_len;
    for (k = 0u; k < KS_KCV_LEN; k++) {
        out[6u + k] = info.kcv[k];
    }
    out[9]  = (uint8_t)(info.contador_uso >> 24);
    out[10] = (uint8_t)(info.contador_uso >> 16);
    out[11] = (uint8_t)(info.contador_uso >> 8);
    out[12] = (uint8_t)(info.contador_uso);
    *out_len = 13u;
    return STATUS_OK;
}

/* ------------------------------------------------------------------ */
/* Tabela de comandos                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t       opcode;
    uint32_t      states;      /* mascara de estados permitidos */
    cmd_handler_t handler;
} cmd_entry_t;

/* Checklist do CLAUDE.md para cada linha nova:
 *   - em quais estados e permitido?
 *   - exige dual control?
 *   - o que vaza se chamado em laco com entradas escolhidas?
 *   - respeita exportability do slot?
 *   - entra no log de auditoria ANTES da execucao?
 *
 * Os tres comandos da fase 1 sao informativos, sem parametro e sem acesso a
 * key store: nao vazam nada em laco alem da propria existencia do
 * dispositivo. Nenhum exige dual control. */
static const cmd_entry_t g_cmds[] = {
    { CMD_PING,        ST_NORMAL,               h_ping        },
    { CMD_GET_VERSION, ST_NORMAL,               h_get_version },
    { CMD_GET_DNA,     ST_NORMAL,               h_get_dna     },

    /* Fase 2. AES e HMAC so em UNINITIALIZED porque recebem chave em
     * claro -- ver cmd.h. Nao e convencao: e esta mascara. */
    { CMD_AES_ENC,     ST_UNINIT,               h_aes_enc     },
    { CMD_AES_DEC,     ST_UNINIT,               h_aes_dec     },
    { CMD_SHA256,      ST_NORMAL,               h_sha256      },
    { CMD_HMAC,        ST_UNINIT,               h_hmac        },
    { CMD_RANDOM,      ST_NORMAL,               h_random      },

    /* SELFTEST responde ate em TAMPERED, de proposito. Ver o handler. */
    { CMD_SELFTEST,    ST_NORMAL | ST_TAMPERED, h_selftest    },

    /* Fase 3 -- cerimonia de LMK.
     *
     * LOAD_COMPONENT so em UNINITIALIZED e SET_STATE so em AUTHORIZED: as
     * duas mascaras juntas desenham a cerimonia como uma ESCADA de uma via.
     * Carregou os tres -> AUTHORIZED, e o comando de carregar some. Ativou
     * -> OPERATIONAL, e o de ativar some. Nenhum degrau se repete, e nao ha
     * como descer sem apagar (ZEROIZE).
     *
     * Os dois exigem dual control, e isso NAO esta na tabela de proposito:
     * a mascara diz "em que estado", nao "quem autoriza". Misturar as duas
     * coisas numa coluna so faria a leitura da tabela depender de saber
     * qual bit significa o que. O dual control fica dentro do handler,
     * onde ele pode recusar sem gastar o rearme. */
    { CMD_LMK_LOAD_COMPONENT, ST_UNINIT, h_lmk_load_component },
    { CMD_LMK_STATUS,         ST_NORMAL, h_lmk_status         },
    { CMD_SET_STATE,          ST_AUTH,   h_set_state          },

    /* Comandos de chave: mesma mascara, nenhum com dual control. O que
     * os protege e o embrulho e a `exportabilidade`, nao uma pessoa. */
    { CMD_GEN_KEY,            ST_OPER,   h_gen_key            },
    { CMD_EXPORT_KEY,         ST_OPER,   h_export_key         },
    { CMD_IMPORT_KEY,         ST_OPER,   h_import_key         },
    { CMD_KEY_INFO,           ST_OPER,   h_key_info           },

    /* ZEROIZE e o UNICO comando permitido em todo estado -- ver o handler.
     * Nao ha estado do qual apagar a chave seja a resposta errada. */
    { CMD_ZEROIZE, ST_NORMAL | ST_TAMPERED, h_zeroize            },
};

#define N_CMDS (sizeof(g_cmds) / sizeof(g_cmds[0]))

/* ------------------------------------------------------------------ */
/* Buffers -- estaticos, sem alocacao dinamica (CLAUDE.md)             */
/* ------------------------------------------------------------------ */

/* rx: LEN(2) + CMD(1) + PAYLOAD + CRC(4). Guardamos o frame inteiro,
 * inclusive LEN, porque o CRC cobre LEN. */
static uint8_t  g_rx[2u + CMD_MAX_LEN + 4u];
static uint8_t  g_tx[2u + CMD_MAX_LEN + 4u];

/* Payload da resposta, escrito pelos handlers. Estatico e nao na pilha: a
 * pilha vive na DMEM de 8 KB e 512 bytes de quadro por comando e caro. */
static uint8_t  g_out[CMD_MAX_PAYLOAD];

/* ------------------------------------------------------------------ */
/* Recepcao                                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    RX_LEN_HI = 0,
    RX_LEN_LO,
    RX_BODY,      /* CMD + PAYLOAD */
    RX_CRC
} rx_state_t;

static rx_state_t g_rx_state;
static uint16_t   g_rx_len;      /* LEN anunciado */
static uint16_t   g_rx_got;      /* bytes ja recebidos do campo corrente */
static uint64_t   g_rx_deadline; /* 0 = nenhum frame em curso */

static uint64_t ms_from_now(uint32_t ms)
{
    /* O CLINT conta na frequencia do clock do sistema. */
    uint64_t ticks = ((uint64_t)NEORV32_SYSINFO->CLK / 1000ull) * (uint64_t)ms;
    return neorv32_clint_time_get() + ticks;
}

static void rx_reset(void)
{
    g_rx_state    = RX_LEN_HI;
    g_rx_len      = 0u;
    g_rx_got      = 0u;
    g_rx_deadline = 0u;
}

static void send_frame(uint8_t status, const uint8_t *payload, uint16_t plen)
{
    uint16_t len = (uint16_t)(plen + 1u);   /* STATUS + payload */
    uint32_t n   = 0u;

    g_tx[n++] = (uint8_t)(len >> 8);
    g_tx[n++] = (uint8_t)(len & 0xFFu);
    g_tx[n++] = status;

    for (uint16_t i = 0u; i < plen; i++) {
        g_tx[n++] = payload[i];
    }

    uint32_t crc = crc32_hsm(g_tx, n);
    g_tx[n++] = (uint8_t)(crc >> 24);
    g_tx[n++] = (uint8_t)(crc >> 16);
    g_tx[n++] = (uint8_t)(crc >> 8);
    g_tx[n++] = (uint8_t)(crc);

    for (uint32_t i = 0u; i < n; i++) {
        neorv32_uart0_putc((char)g_tx[i]);
    }
}

/* Responde um erro de transporte e volta a procurar inicio de frame. */
static void fail(uint8_t status)
{
    send_frame(status, NULL, 0u);
    rx_reset();
}

static void dispatch(void)
{
    const uint8_t *body     = &g_rx[2];              /* CMD + payload */
    uint8_t        opcode   = body[0];
    const uint8_t *payload  = &body[1];
    uint16_t       plen     = (uint16_t)(g_rx_len - 1u);

    /* CRC cobre LEN + CMD + PAYLOAD, tudo menos os 4 bytes do proprio CRC */
    uint32_t crc_calc = crc32_hsm(g_rx, (uint32_t)(2u + g_rx_len));
    const uint8_t *c  = &g_rx[2u + g_rx_len];
    uint32_t crc_rx   = ((uint32_t)c[0] << 24) | ((uint32_t)c[1] << 16) |
                        ((uint32_t)c[2] << 8)  | (uint32_t)c[3];

    if (crc_calc != crc_rx) {
        fail(STATUS_BAD_CRC);
        return;
    }

    /* TODO fase 3: o log de auditoria e gravado AQUI, antes de executar.
     * Depois da execucao registraria so o que deu certo, o que e inutil
     * como trilha forense (PLANO.md secao 5). */

    const cmd_entry_t *e = NULL;
    for (uint32_t i = 0u; i < N_CMDS; i++) {
        if (g_cmds[i].opcode == opcode) {
            e = &g_cmds[i];
            break;
        }
    }

    if (e == NULL) {
        fail(STATUS_UNKNOWN_CMD);
        return;
    }

    if ((e->states & state_mask()) == 0u) {
        fail(STATUS_WRONG_STATE);
        return;
    }

    uint16_t out_len = 0u;

    hsm_status_t st = e->handler(payload, plen, g_out, &out_len);

    if (out_len > CMD_MAX_PAYLOAD) {
        /* Handler com bug: melhor recusar do que transmitir DMEM adjacente. */
        out_len = 0u;
        st = STATUS_INTERNAL_ERROR;
    }

    send_frame((uint8_t)st, g_out, out_len);

    /* Limpeza dos buffers depois de cada comando.
     * Fase 1 nao movimenta chave, mas na fase 3 estes mesmos buffers
     * carregam componente de LMK e key block. O habito comeca agora. */
    wipe(g_out, sizeof(g_out));
    wipe(g_rx, sizeof(g_rx));
    wipe(g_tx, sizeof(g_tx));

    rx_reset();
}

static void rx_byte(uint8_t b)
{
    /* Rearma a cada byte: o timeout e entre bytes, nao do frame inteiro.
     * A diferenca importa para payload grande -- um key block TR-31 da fase
     * 3 leva ~45 ms a 115200 baud, e um timeout de frame teria de ser
     * afrouxado ate deixar de proteger. */
    g_rx_deadline = ms_from_now(CMD_INTERBYTE_TIMEOUT_MS);

    switch (g_rx_state) {

    case RX_LEN_HI:
        g_rx[0]    = b;
        g_rx_state = RX_LEN_LO;
        break;

    case RX_LEN_LO:
        g_rx[1]  = b;
        g_rx_len = (uint16_t)(((uint16_t)g_rx[0] << 8) | (uint16_t)b);

        if (g_rx_len < CMD_MIN_LEN || g_rx_len > CMD_MAX_LEN) {
            /* LEN invalido: nao da para saber onde este frame termina, entao
             * responder e resincronizar pelo timeout de inter-byte. Continuar
             * lendo com um LEN absurdo seria seguir o atacante. */
            fail(STATUS_BAD_LEN);
            break;
        }

        g_rx_got   = 0u;
        g_rx_state = RX_BODY;
        break;

    case RX_BODY:
        g_rx[2u + g_rx_got] = b;
        g_rx_got++;
        if (g_rx_got == g_rx_len) {
            g_rx_got   = 0u;
            g_rx_state = RX_CRC;
        }
        break;

    case RX_CRC:
        g_rx[2u + g_rx_len + g_rx_got] = b;
        g_rx_got++;
        if (g_rx_got == 4u) {
            dispatch();
        }
        break;

    default:
        rx_reset();
        break;
    }
}

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

void cmd_init(void)
{
    rx_reset();
    wipe(g_rx, sizeof(g_rx));
    wipe(g_tx, sizeof(g_tx));
}

void cmd_poll(void)
{
    while (neorv32_uart0_char_received()) {
        rx_byte((uint8_t)neorv32_uart0_char_received_get());
    }

    /* Resincronizacao por timeout.
     *
     * Este bloco e o que satisfaz "frame malformado nunca trava a maquina
     * de estados". Sem ele, um host que morre no meio de um frame deixa o
     * parser esperando bytes que nunca chegam, e o dispositivo fica mudo
     * para sempre -- negacao de servico com um unico byte. */
    if (g_rx_state != RX_LEN_HI && g_rx_deadline != 0u) {
        if (neorv32_clint_time_get() > g_rx_deadline) {
            fail(STATUS_TIMEOUT);
        }
    }
}
