/* fw/src/flash.c -- driver da flash SPI (MT25QL128)
 *
 * FRONTEIRA: dentro. Ver flash.h -- e a regiao de cima da flash e tratada
 * como memoria segura do dispositivo.
 *
 * SPI modo 0, uma linha, 12,5 MHz. O datasheet permite bem mais para o
 * READ (0x03), mas o CCLK passa pela STARTUPE2 e o caminho de volta do
 * MISO nao tem restricao de timing no XDC; 40 ns de meio periodo sobram
 * para isso, e o volume de dados aqui e de poucos KB.
 */
#include <neorv32.h>

#include "flash.h"

#define CMD_READ_ID   0x9Fu
#define CMD_RDSR      0x05u
#define CMD_WREN      0x06u
#define CMD_READ      0x03u
#define CMD_PP        0x02u
#define CMD_SSE       0x20u

#define SR_WIP        0x01u
#define SR_WEL        0x02u

/* Tempos maximos do datasheet com folga: 4 KB em ate 400 ms, pagina em
 * ate ~2 ms. */
#define TIMEOUT_SSE_MS  1000u
#define TIMEOUT_PP_MS     10u

static int g_presente;

static uint8_t xfer(uint8_t b)
{
    return neorv32_spi_transfer(b);
}

static void cs_on(void)  { neorv32_spi_cs_en(0); }
static void cs_off(void) { neorv32_spi_cs_dis(); }

static int na_regiao(uint32_t addr, uint32_t n)
{
    /* A guarda do bitstream. Toda escrita passa por aqui, e so por aqui. */
    if (addr < FLASH_REGIAO_INICIO) {
        return 0;
    }
    if ((n > (FLASH_REGIAO_FIM - FLASH_REGIAO_INICIO)) ||
        (addr > (FLASH_REGIAO_FIM - n))) {
        return 0;
    }
    return 1;
}

static uint8_t le_status(void)
{
    uint8_t s;
    cs_on();
    (void)xfer(CMD_RDSR);
    s = xfer(0xFFu);
    cs_off();
    return s;
}

static int espera(uint32_t ms)
{
    uint64_t fim = neorv32_clint_time_get() +
                   ((uint64_t)NEORV32_SYSINFO->CLK / 1000ull) * (uint64_t)ms;

    while (le_status() & SR_WIP) {
        if (neorv32_clint_time_get() > fim) {
            return -1;
        }
    }
    return 0;
}

static int habilita_escrita(void)
{
    cs_on();
    (void)xfer(CMD_WREN);
    cs_off();
    return (le_status() & SR_WEL) ? 0 : -1;
}

static void endereco(uint8_t cmd, uint32_t addr)
{
    (void)xfer(cmd);
    (void)xfer((uint8_t)(addr >> 16));
    (void)xfer((uint8_t)(addr >> 8));
    (void)xfer((uint8_t)addr);
}

int flash_init(void)
{
    uint8_t id[3];

    g_presente = 0;
    if (neorv32_spi_available() == 0) {
        return -1;
    }

    /* prescaler /2 (codigo 0), divisor 1+1: 100 / (2*2*2) = 12,5 MHz */
    neorv32_spi_setup(0, 1, 0, 0);

    /* A STARTUPE2 engole os tres primeiros ciclos de USRCCLKO (UG470).
     * Um byte descartavel com o CS em alto os consome sem a flash ver. */
    (void)xfer(0x00u);

    cs_on();
    (void)xfer(CMD_READ_ID);
    id[0] = xfer(0xFFu);
    id[1] = xfer(0xFFu);
    id[2] = xfer(0xFFu);
    cs_off();

    /* Micron, MT25QL, 128 Mbit. Outra peca nao e "quase certa": e outro
     * mapa de setores, e a guarda do bitstream deixaria de valer. */
    if ((id[0] != 0x20u) || (id[1] != 0xBAu) || (id[2] != 0x18u)) {
        return -1;
    }
    g_presente = 1;
    return 0;
}

int flash_presente(void)
{
    return g_presente;
}

int flash_le(uint32_t addr, uint8_t *buf, uint32_t n)
{
    uint32_t i;

    if (!g_presente || (buf == 0) || !na_regiao(addr, n)) {
        return -1;
    }
    cs_on();
    endereco(CMD_READ, addr);
    for (i = 0u; i < n; i++) {
        buf[i] = xfer(0xFFu);
    }
    cs_off();
    return 0;
}

int flash_apaga_4k(uint32_t addr)
{
    if (!g_presente || ((addr % FLASH_SUBSETOR) != 0u) ||
        !na_regiao(addr, FLASH_SUBSETOR)) {
        return -1;
    }
    if (habilita_escrita() != 0) {
        return -1;
    }
    cs_on();
    endereco(CMD_SSE, addr);
    cs_off();
    return espera(TIMEOUT_SSE_MS);
}

int flash_grava(uint32_t addr, const uint8_t *buf, uint32_t n)
{
    uint32_t pedaco, i;

    if (!g_presente || (buf == 0) || !na_regiao(addr, n)) {
        return -1;
    }

    while (n > 0u) {
        /* Uma PAGE PROGRAM nao atravessa pagina: o que passasse do fim
         * DARIA A VOLTA e cairia no comeco da mesma pagina. */
        pedaco = FLASH_PAGINA - (addr % FLASH_PAGINA);
        if (pedaco > n) {
            pedaco = n;
        }
        if (habilita_escrita() != 0) {
            return -1;
        }
        cs_on();
        endereco(CMD_PP, addr);
        for (i = 0u; i < pedaco; i++) {
            (void)xfer(buf[i]);
        }
        cs_off();
        if (espera(TIMEOUT_PP_MS) != 0) {
            return -1;
        }
        addr += pedaco;
        buf  += pedaco;
        n    -= pedaco;
    }
    return 0;
}
