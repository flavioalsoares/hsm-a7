# O código do firmware (C)

Guia de leitura de `fw/`, o programa que roda no processador NEORV32 dentro do
FPGA. Atualizado na fase 4 (2026-10-16).

O firmware é **C99, sem alocação dinâmica e sem libc de verdade**. Tudo é
estático e cabe em duas memórias internas do FPGA: 32 KB de código (IMEM) e
16 KB de dados (DMEM). As duas são Block RAM, e é isso que a regra nº 2 do
projeto chama de "chaves só em BRAM".

```
fw/
  Makefile            usa a infraestrutura do NEORV32; `make image` gera a IMEM
  include/            um .h por módulo, com o contrato e as decisões de projeto
  src/                a implementação
  neorv32_imem_image.vhd   o binário, em VHDL, embutido no bitstream
```

⚠ **O firmware é ROM.** `BOOT_MODE_SELECT = 2`: o código vai dentro do
bitstream, e trocar o firmware exige regerar o bitstream. É o que impede
alguém com acesso à UART de reprogramar o dispositivo e contornar a fronteira
inteira.

---

## 1. Como ler este código

**Os comentários dos `.h` são a documentação principal.** Cada arquivo abre
com o bloco `FRONTEIRA:`, dizendo se ele está dentro ou fora da fronteira
criptográfica e se toca material de chave. As decisões de projeto, com o
porquê, estão nos cabeçalhos, não neste guia. Este guia é o mapa.

A convenção mais importante: **toda função que toca chave diz de que lado
da fronteira opera**, e buffers sensíveis são limpos com `wipe()`, que o
compilador não consegue eliminar (ver §6).

---

## 2. O caminho de um comando, do pino ao handler

```
UART -> cmd_poll() -> rx_byte() -> dispatch() -> log -> estado -> handler -> log -> send_frame()
```

1. **`main.c`** prepara o hardware, roda o POST, restaura o estado da flash e
   entra no laço principal: `cmd_poll()`, `dualctl_poll()`,
   `painel_atualiza()`. Não há interrupção. O caminho de comando é síncrono e
   de passo único, mais fácil de auditar que um handler de IRQ mexendo nos
   mesmos buffers.
2. **`cmd.c`, `rx_byte()`** monta o frame byte a byte numa máquina de
   estados. Se passarem 250 ms sem byte novo, abandona o frame parcial. Sem
   isso, um único byte perdido deixaria o dispositivo mudo para sempre.
3. **`dispatch()`** confere o CRC32 e procura o opcode na tabela `g_cmds[]`.
   Cada linha tem quatro campos:

   ```c
   { CMD_GEN_KEY, ST_OPER, h_gen_key, L },
   //  opcode     estados  handler    entra no log?
   ```

4. **Log de auditoria (fase 4)**: se a linha é `L`, o registro vai para a
   flash **antes** de qualquer outra coisa, inclusive antes de checar o
   estado, porque a tentativa fora de hora também é evento. Se não der para
   gravar, o comando não executa (`LOG_FAIL`), com a exceção do `ZEROIZE`.
5. **Máscara de estados**: se o estado atual não está na máscara, a resposta
   é `WRONG_STATE` e o handler nem é chamado.
6. **O handler** recebe `(in, in_len, out, &out_len)` e devolve um status.
7. O **resultado** é programado no registro do log, a resposta sai, e os três
   buffers (`g_rx`, `g_tx`, `g_out`) são zerados. Eles carregam componentes
   de LMK e key blocks.

⚠ **Dual control não está na tabela.** A máscara responde "em que estado";
quem autoriza é checado **dentro** do handler, que pode recusar sem gastar o
aperto do botão.

---

## 3. Mapa dos módulos

### Infraestrutura

| Arquivo | O que faz |
|---|---|
| `main.c` | boot: UART, CFS presente, POST, flash, log, restauração; o laço principal; o painel de 7 segmentos (2 bits de estado + 1 de dual control pelo GPIO) |
| `cmd.c` / `cmd.h` | o protocolo de frames, a tabela de comandos e todos os handlers. `cmd.h` tem o formato de cada comando e o checklist de segurança dele |
| `state.c` | a máquina de estados `UNINITIALIZED → AUTHORIZED → OPERATIONAL`, mais `TAMPERED`, que é **absorvente**: de lá não se sai por software |
| `dualctl.c` | dual control pelos botões SW2 e SW5. `dualctl_autoriza()` **consome** a autorização; `dualctl_pronto()` é só consulta, para o ponto decimal |
| `wipe.c` | zeroização que o compilador não remove (§6) |

### Criptografia

| Arquivo | O que faz |
|---|---|
| `hsm_cfs.c` | driver do coprocessador no fabric. O hardware faz **um bloco** de AES-256 ECB e **um bloco** de compressão SHA-256; o resto é firmware |
| `aes_modos.c` | AES-CBC. **Não tem parâmetro de chave**: opera sobre a chave já carregada no coprocessador por quem tem direito a ela |
| `sha.c` | SHA-256 de mensagem (o padding do FIPS 180-4 é feito aqui) e HMAC-SHA-256, que hoje só o POST usa (o comando `HMAC` com chave em claro foi removido na fase 3) |
| `cmac.c` | CMAC-AES-256 (SP 800-38B), com verificação em tempo constante |
| `drbg.c` | CTR_DRBG com AES-256 (SP 800-90A), semeado pela fonte de entropia do fabric depois dos health tests. Toda chave gerada sai daqui |
| `kat.c` | o POST: vetores oficiais de AES, SHA, HMAC, CMAC e DRBG, testes de partida da fonte de entropia e testes de função crítica do key store e do key block. Devolve uma máscara de 8 bits, uma por teste, e **os 8 bits acabaram** |

### Chaves

| Arquivo | O que faz |
|---|---|
| `keystore.c` | **o arquivo mais sensível.** Os 16 slots, a LMK, o acumulador de componentes. O tipo que contém chave (`slot_t`) nem aparece no `.h`: nada fora deste arquivo consegue declarar uma variável com chave |
| `tr31.c` | key block X9.143 versão D: derivação de KBEK/KBAK por CMAC, embrulhar e desembrulhar. A segunda implementação está em `host/tr31.py` |

### Fase 4: persistência

| Arquivo | O que faz |
|---|---|
| `flash.c` | driver SPI da MT25QL128. **Recusa qualquer escrita abaixo de 4 MB**, onde está o bitstream |
| `persist.c` | o registro persistente: LMK, estado e slots embrulhados, em duas cópias (A/B) com contador e CRC |
| `audit_log.c` | o log de auditoria: registros de 16 bytes num anel de 64 KB, gravados antes de executar |

---

## 4. As portas do key store

A API de `keystore.h` é **assimétrica de propósito**, e é o desenho que mais
vale entender:

| Função | Devolve chave? | Quem chama |
|---|---|---|
| `keystore_usa_aes(h, modo)` | **não**: carrega no coprocessador, depois de checar o `modo` do slot | `ENCRYPT`, `DECRYPT` |
| `keystore_cmac(h, ...)` / `keystore_cmac_verifica(...)` | **não**: calcula dentro de `keystore.c` | `MAC_GENERATE`, `MAC_VERIFY` |
| `lmk_deriva_kb(kbek, kbak)` | só as **subchaves derivadas**, nunca a LMK | `EXPORT_KEY`, `IMPORT_KEY` |
| `keystore_exporta(h, out)` | **sim**, e recusa `exportabilidade = 'N'` | só `EXPORT_KEY` |
| `keystore_registro_monta(...)` | o registro persistente, com a LMK em claro e os slots **embrulhados** | só `persist.c` (fase 4) |

Um `keystore_get_key()` genérico transformaria cada checagem em convenção, e
convenção é o que se esquece no caminho raro. **Se um código novo precisar
da chave em claro, a pergunta certa não é "como faço isso funcionar", é "por
que este código precisa da chave?".**

Outros pontos do key store:

- **Modos de uso em dois grupos que não se cruzam**: cifra (`E`, `D`, `B`) e
  MAC (`G`, `V`, `C`), mais o `N`. Uma chave de cifra não autentica, e uma de
  MAC não cifra. A checagem mora no key store, num lugar só.
- **Handle 0 é inválido.** Os válidos vão de 1 a 16, para que um campo
  esquecido em zero não caia num slot por acidente.
- **A LMK fica fora do vetor de slots**: sem handle, e zeroizá-la apaga todos
  os slots junto.
- **LMK zerada é recusada** no terceiro componente (`lmk_componente()`
  devolve -2, o handler responde `BAD_PARAM`) e a cerimônia recomeça em 0
  de 3. Acontece quando o último componente é o XOR dos anteriores. LMK
  *fraca* não é checada: a qualidade do componente é do custodiante.
- **O KCV** (3 bytes de `AES(chave, bloco de zeros)`) é o único dado derivado
  de uma chave que sai da fronteira. É curto de propósito: basta para pegar
  um erro de digitação e não serve para atacar.

---

## 5. Fase 4: o que acontece na flash

```
0x000000  bitstream                intocável (flash.c recusa)
0x400000  registro persistente, A  4 KB
0x401000  registro persistente, B  4 KB
0x410000  log de auditoria         64 KB
```

**Por que a LMK está em claro na flash:** decisão de projeto educacional,
tomada por falta de um lugar seguro para guardá-la nesta placa. A explicação
completa está em `doc/fase4-notas.md`, na seção de abertura, e a regra nº 2
do `CLAUDE.md` foi reescrita para refleti-la.

### Boot (`main.c`)

```
flash_init()  -> confere o JEDEC ID (20 BA 18); sem ele, nada de flash
log_init()    -> acha o fim do log lendo o 1º registro de cada subsetor
kat_post()    -> POST
persist_restaura() -> LMK + estado + slots, da cópia válida mais nova
log_registra(BOOT) -> registro de boot: POST, flash, restauração
```

### Gravar (`persist_salva`)

1. `keystore_registro_monta()` escreve num buffer estático a LMK, o KCV dela e
   cada slot ocupado como `índice || key block`.
2. `persist.c` acrescenta o cabeçalho (`"HSM4"`, versão, estado, comprimento,
   contador) e o CRC32.
3. Apaga a **cópia mais velha**, grava e **lê de volta para conferir**.
4. Zera o buffer, que continha a LMK.

Quem chama, e o que faz se falhar: ver a tabela em `doc/fase4-notas.md`. O
princípio: **chave que o dispositivo diz ter guardado tem de estar
guardada**, e por isso `GEN_KEY` e similares desfazem o slot quando a flash
falha.

### O log (`audit_log.c`)

O registro vai para a flash com o resultado em `0xFF` ("pendente"). Depois do
handler, **só aquele byte** é programado. Não precisa apagar, porque flash só
desce bits. Um registro que ficou em `0xFF` é um comando que começou e não
terminou.

O registro `seq` mora na posição `seq % 4096`, então achar um registro antigo
é conta, não busca.

---

## 6. Zeroização: por que existe `wipe()`

```c
void wipe(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) { *q++ = 0u; }
    __asm__ __volatile__("" ::: "memory");
}
```

Um `memset` no fim de uma função, sobre um buffer que ninguém lê depois, é
**eliminado pelo compilador**: para ele, é escrita morta. O `volatile` obriga
cada escrita a acontecer, e a barreira impede que ela seja movida.

`wipe_padrao()` faz duas passadas, `0xAA` (metade dos bits em 1) e depois
zeros, e é usada nas zeroizações de verdade (`keystore_init()`). Depois dela,
`keystore_prova_zeroizacao()` relê a região inteira, também com `volatile`,
e exige zero em todo byte. Sem o `volatile`, o compilador "provaria" que
acabou de zerar e trocaria a varredura por `return 1`.

---

## 7. Como acrescentar um comando

A ordem do `CLAUDE.md`: **entrada na tabela, verificação de estado, teste.**

1. O opcode em `cmd.h`, com o formato e o **checklist**: em que estados, se
   exige dual control, o que vaza se chamado em laço, se respeita
   `exportabilidade`, se entra no log.
2. O handler em `cmd.c`. Ele confere `in_len` **antes** de ler o payload e,
   se exigir dual control, valida tudo **antes** de chamar
   `dualctl_autoriza()`, para que um erro do host não gaste o aperto do
   operador.
3. A linha em `g_cmds[]`, com a máscara de estados e `L` ou `I`.
4. O subcomando no `host/hsmtool.py`.
5. Um testbench em `sim/tb/` que o exercite pelo firmware real. É a regra nº 4:
   nada vai para a placa sem testbench passando.

Se o comando mexe em slot, ele chama `persist_salva()` e desfaz a mudança
quando a flash falha.

---

## 8. Compilar e testar

```bash
make -C fw image          # -> fw/neorv32_imem_image.vhd (exigido pelo build)
./scripts/sim.sh          # recompila o firmware sozinho se o C for mais novo
```

`scripts/sim.sh` roda o firmware de verdade, dentro do SoC simulado, contra
os testbenches. ⚠ Até 2026-08-29 ele não recompilava o firmware, e uma
sabotagem deliberada no C **passou** na simulação, porque o código sabotado
nunca chegou a ser compilado.

Toolchain: `gcc-riscv64-unknown-elf` **e** `picolibc-riscv64-unknown-elf`.
