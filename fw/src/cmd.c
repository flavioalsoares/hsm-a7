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
