/* fw/include/kat.h -- POST: known-answer tests no boot
 *
 * FRONTEIRA: dentro. As chaves dos vetores são públicas (vêm do NIST e do
 * IETF), mas passam pelos mesmos caminhos que as chaves de verdade — e por
 * isso são zeroizadas do mesmo jeito. Tratar material de teste com menos
 * cuidado ensina o hábito errado.
 *
 * ---------------------------------------------------------------------
 * POR QUE UM HSM RODA KAT A CADA BOOT
 *
 * Não é desconfiança do código: o código é o mesmo de ontem. É
 * desconfiança do HARDWARE e do CAMINHO. Entre um boot e o outro podem ter
 * mudado a temperatura, a alimentação, o conteúdo de uma Block RAM que não
 * foi inicializada, um bit de configuração. Este projeto já viu
 * exatamente isso acontecer (`doc/bancada.md`).
 *
 * É o requisito de self-test do FIPS 140-3, e a lógica dele é simples: um
 * módulo criptográfico que não consegue provar que calcula certo **agora**
 * não deve aceitar comando nenhum. Cripto errada é pior que cripto
 * ausente, porque parece que funcionou.
 *
 * ---------------------------------------------------------------------
 * O QUE ELE COBRE, E O QUE DELIBERADAMENTE NÃO
 *
 * Cobre: AES-256 ECB (cifra e decifra), SHA-256, HMAC-SHA-256 e CTR_DRBG,
 * cada um contra vetores oficiais, **através do mapa de registradores do
 * coprocessador** — que é o caminho que o firmware usa de verdade.
 *
 * Não cobre exaustivamente: são 1620 vetores de AES, 65 de SHA e 480 de
 * DRBG disponíveis, e eles rodam em SIMULAÇÃO, onde custam segundos e
 * não ocupam IMEM. O POST prova integridade do caminho neste boot, não
 * corretude do algoritmo — essa já foi provada antes de o bitstream
 * existir.
 *
 * A distinção importa: se um KAT passa no testbench e falha no POST, o
 * problema está no barramento ou no silício, não no algoritmo.
 */
#ifndef KAT_H
#define KAT_H

/* Cada bit identifica um teste que reprovou, para o diagnóstico dizer
 * QUAL falhou e não apenas que algo falhou. */
#define KAT_OK          0x00u
#define KAT_FALHA_AES   0x01u
#define KAT_FALHA_SHA   0x02u
#define KAT_FALHA_HMAC  0x04u
#define KAT_FALHA_DRBG  0x08u
#define KAT_FALHA_TRNG  0x10u

/* Roda o POST inteiro. Devolve KAT_OK ou a união dos bits que falharam.
 *
 * Não para no primeiro erro: roda tudo e reporta tudo. Parar cedo
 * economiza microssegundos e esconde informação de diagnóstico numa
 * situação em que o dispositivo já não vai operar mesmo. */
unsigned kat_post(void);

/* Último resultado, para o comando SELFTEST e para o log. */
unsigned kat_ultimo(void);

#endif /* KAT_H */
