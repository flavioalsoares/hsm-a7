/* fw/include/dualctl.h -- dual control pelos dois botoes fisicos
 *
 * FRONTEIRA: dentro. Este modulo nao ve material de chave, mas e ele que
 * decide se um comando que MEXE em chave pode rodar. Um defeito aqui nao
 * vaza nada sozinho -- so autoriza quem nao devia.
 *
 * O principio (PLANO.md secao 4): nenhuma operacao sobre a chave mestra
 * acontece por decisao de uma pessoa so. No mundo real isso e crachá, sala
 * fechada e duas pessoas presentes; aqui sao dois botoes de bancada, e a
 * diferenca importa -- ver "Honestidade sobre o que isto NAO e", abaixo.
 *
 * Ligacao fisica (doc/pinout.md, verificado em hardware 2026-08-21):
 *
 *     SW2 -> M6 -> btn_a -> debounce -> GPIO entrada bit 0
 *     SW5 -> P6 -> btn_b -> debounce -> GPIO entrada bit 1
 *
 * Os botoes sao ativos em nivel BAIXO na placa, mas rtl/top/hsm_top.v ja
 * inverte antes de entregar ao SoC. No firmware, portanto:
 *
 *     1 = pressionado
 *
 * Ler isso ao contrario inverteria o dual control em silencio: o comando
 * passaria com os botoes SOLTOS e seria recusado com eles apertados. Como
 * o caminho feliz de um teste apressado e "aperto e funciona", vale o
 * lembrete.
 *
 * --------------------------------------------------------------------
 * Aperto NOVO a cada autorizacao
 * --------------------------------------------------------------------
 *
 * Nao basta que os dois botoes estejam pressionados AGORA. Entre duas
 * autorizacoes, os dois tem de ter sido vistos SOLTOS.
 *
 * Sem essa exigencia, fita adesiva sobre os dois botoes -- ou um jumper, ou
 * um contato colado -- carregaria os tres componentes da LMK sozinha, e o
 * dual control viraria teatro. Com ela, cada componente custa um gesto
 * deliberado, e um botao travado em "pressionado" deixa de autorizar
 * qualquer coisa em vez de autorizar tudo.
 *
 * E a mesma ideia do debounce em rtl/soc/debounce.v, um nivel acima: la se
 * exige que o contato pare quieto, aqui se exige que o operador solte.
 *
 * --------------------------------------------------------------------
 * Honestidade sobre o que isto NAO e
 * --------------------------------------------------------------------
 *
 * Dois botoes na mesma placa cabem nas duas maos de uma pessoa. Este
 * mecanismo prova PRESENCA FISICA junto ao equipamento, e nao prova que
 * duas pessoas consentiram. Num HSM de verdade a separacao vem de smart
 * card por custodiante, ou de chave fisica, ou dos dois.
 *
 * Fica como esta de proposito, e documentado: o valor didatico esta em ver
 * o comando ser recusado por uma condicao que o host NAO controla.
 */
#ifndef DUALCTL_H
#define DUALCTL_H

#include <stdint.h>

/* Bits do GPIO de entrada -- ver rtl/top/hsm_top.v */
#define DUALCTL_BIT_A   0u    /* SW2 / M6 */
#define DUALCTL_BIT_B   1u    /* SW5 / P6 */

/* Comeca DESARMADO. Um dispositivo que acaba de ligar com os dois botoes
 * pressionados nao autoriza nada ate serem soltos -- que e exatamente o
 * caso do botao travado. */
void dualctl_init(void);

/* Observa os botoes e rearma quando os dois estao soltos.
 *
 * Chamar do laco principal. Nao ha interrupcao aqui de proposito: o
 * caminho de autorizacao inteiro e sincrono e de passo unico, mais facil
 * de auditar. */
void dualctl_poll(void);

/* CONSOME uma autorizacao.
 *
 * Devolve 1 se, neste instante, os dois botoes estao pressionados E houve
 * um rearme desde a ultima autorizacao. Nesse caso desarma, de modo que a
 * proxima autorizacao exija soltar e apertar de novo.
 *
 * Devolve 0 caso contrario, sem efeito colateral -- uma tentativa recusada
 * nao gasta o rearme, senao um host malicioso poderia negar o servico ao
 * operador chamando o comando em laco. */
int dualctl_autoriza(void);

#endif /* DUALCTL_H */
