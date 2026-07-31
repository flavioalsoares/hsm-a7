/* fw/include/wipe.h -- zeroizacao que o compilador nao pode remover
 *
 * FRONTEIRA: dentro. Existe para garantir que material sensivel nao
 * sobreviva ao escopo em que foi usado.
 *
 * Por que nao memset: um memset no fim de uma funcao, sobre um buffer que
 * nao e mais lido, e "dead store". O compilador tem permissao para elimina-lo
 * e o faz com -O2/-Os. O buffer fica na DMEM com a chave intacta.
 *
 * A solucao aqui e ponteiro volatile: cada escrita e um efeito colateral
 * observavel e nao pode ser descartada. A barreira de memoria depois impede
 * reordenamento em relacao ao resto.
 *
 * Fase 1 ainda nao manipula chave, mas o habito comeca agora: os buffers de
 * frame vao carregar componente de LMK e key block na fase 3, e retroajustar
 * limpeza depois e como se lembra tarde demais.
 */
#ifndef WIPE_H
#define WIPE_H

#include <stddef.h>
#include <stdint.h>

void wipe(void *p, size_t n);

#endif /* WIPE_H */
