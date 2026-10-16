/* fw/include/flash.h -- driver da flash SPI (MT25QL128)
 *
 * FRONTEIRA: dentro. A flash e a memoria persistente do dispositivo, e
 * este projeto a TRATA COMO MEMORIA SEGURA -- decisao de 2026-10-15, ver
 * CLAUDE.md (regra 2) e doc/fase4-notas.md. Num HSM comercial esse papel
 * e de uma memoria com bateria dentro do invólucro com deteccao de
 * violacao; aqui e um chip SPI na placa, e a diferenca esta documentada
 * em vez de mitigada.
 *
 * ---------------------------------------------------------------------
 * A FLASH E A MESMA DO BITSTREAM
 *
 * Os primeiros ~2 MB guardam a configuracao do FPGA. Apagar um setor la
 * deixa a placa sem subir ate alguem regravar por JTAG. Por isso o driver
 * RECUSA qualquer ERASE ou PROGRAM abaixo de FLASH_REGIAO_INICIO, e a
 * recusa mora aqui, no unico lugar por onde toda escrita passa -- nao nos
 * chamadores.
 *
 *   0x000000  bitstream                 intocavel
 *   0x400000  registro persistente, A   4 KB   (fw/src/persist.c)
 *   0x401000  registro persistente, B   4 KB
 *   0x410000  log de auditoria          64 KB  (fw/src/audit_log.c)
 */
#ifndef FLASH_H
#define FLASH_H

#include <stdint.h>

#define FLASH_REGIAO_INICIO  0x400000u   /* 4 MB: nada abaixo disto   */
#define FLASH_REGIAO_FIM     0x480000u   /* 512 KB de regiao do HSM   */
#define FLASH_SUBSETOR       4096u
#define FLASH_PAGINA         256u

/* Prepara o SPI e confere o JEDEC ID. Devolve 0 se a flash certa
 * respondeu. Sem isso, todo o resto devolve erro. */
int flash_init(void);

/* 1 se flash_init() encontrou a MT25QL128. */
int flash_presente(void);

/* Leitura. Qualquer endereco da regiao do HSM. Devolve 0 em sucesso. */
int flash_le(uint32_t addr, uint8_t *buf, uint32_t n);

/* Apaga o subsetor de 4 KB que contem `addr` (alinhado). Recusa fora da
 * regiao. Espera terminar. Devolve 0 em sucesso. */
int flash_apaga_4k(uint32_t addr);

/* Programa `n` bytes, quebrando nas fronteiras de pagina. So DESCE bits:
 * o chamador apaga antes. Recusa fora da regiao. Devolve 0 em sucesso. */
int flash_grava(uint32_t addr, const uint8_t *buf, uint32_t n);

#endif /* FLASH_H */
