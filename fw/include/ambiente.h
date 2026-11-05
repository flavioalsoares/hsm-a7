/* fw/include/ambiente.h -- resposta a condicao ambiental fora da faixa
 *
 * FRONTEIRA: dentro. Nao ve bytes de chave, mas manda apaga-los.
 *
 * O hardware detecta e retem (rtl/crypto/hsm_xadc.v); aqui mora a politica.
 * Nao ha dual control: pessoas precisam de duas pessoas, um dispositivo que
 * se descobre comprometido nao precisa de ninguem. Ver cmd.h, ZEROIZE.
 *
 * A ordem da resposta e a excecao declarada a "log antes de executar":
 *
 *   1. apaga a BRAM e o CFS, em microssegundos
 *   2. vai para TAMPERED
 *   3. grava o registro no log
 *   4. apaga a copia da flash
 *   5. programa o resultado no registro
 *
 * Tensao caindo pode ser energia acabando. A chave some antes de se gastar
 * um milissegundo escrevendo na flash.
 */
#ifndef AMBIENTE_H
#define AMBIENTE_H

/* No boot, depois do POST e antes de restaurar da flash. Espera a primeira
 * leitura; sensor que nao responde e violacao. Devolve 1 se respondeu a
 * uma violacao, 0 se o ambiente esta bom. */
int ambiente_boot(void);

/* No laco principal. Devolve 1 se acabou de responder a uma causa nova. */
int ambiente_poll(void);

#endif /* AMBIENTE_H */
