# Fase 2 — notas de implementação

Objetivo da fase (`PLANO.md` §3): primitivas corretas e verificáveis.
**Correção antes de desempenho.**

Estado: **em andamento.** Os vetores e os cores estão prontos e verificados;
a integração ao CFS ainda não começou.

---

## Concluído

### Vetores KAT (`vectors/`)

Baixados das fontes oficiais em 2026-07-31, com hash registrado em
`vectors/MANIFEST.txt`. Nada foi escrito de memória.

| Diretório | Origem | Conteúdo |
|---|---|---|
| `aes/` | NIST CAVP (AESAVS) | AES-256 ECB e CBC, os 4 tipos de vetor |
| `sha/` | NIST CAVP (SHAVS) | SHA-256, mensagens curtas e longas |
| `hmac/` | IETF RFC 4231 | HMAC-SHA-256 |
| `drbg/` | NIST CAVP (SP 800-90A) | CTR_DRBG AES-256 |

```bash
./scripts/fetch-vectors.sh --check   # confere o repositório
./scripts/fetch-vectors.sh           # rebaixa e reextrai
```

Rodar o segundo sobre um repositório limpo termina **sem nenhuma
diferença** — verificado. Isso é o que sustenta a regra inviolável nº 5: "se
um KAT falha, o bug está no código, não no vetor" só vale se a procedência
do vetor for verificável por terceiros.

Os vetores são versionados, ao contrário dos outros derivados do projeto.
Dois motivos: um POST que depende de rede não é um POST, e o NIST reorganiza
URLs.

### Cores criptográficos

| Submódulo | Origem | Commit |
|---|---|---|
| `third_party/aes` | secworks/aes | `80dc471` |
| `third_party/sha256` | secworks/sha256 | `837c5cc` |

Fixados por **SHA de commit**, não por tag: o `aes` não tem tag nenhuma e a
única do `sha256` é de 2023, dois anos e meio atrás. SHA de commit é
igualmente imutável, que era o motivo de evitar branch (`doc/submodulos.md`).

### Testbenches

```
tb_aes_kat     405 × 4 (ECB/CBC, cifra/decifra) = 1620 vetores   PASS
tb_sha256_kat  65 mensagens, 74 blocos                            PASS
```

**Por que os quatro tipos do AESAVS, e não só um:**

- `GFSbox` — textos escolhidos, chave zero
- `KeySbox` — chaves escolhidas, texto zero
- `VarKey` — cada bit da chave ligado isoladamente, 256 vetores. Pega
  indexação errada na expansão de chave.
- `VarTxt` — cada bit do bloco ligado isoladamente, 128 vetores. Pega ordem
  de byte, rotação e permutação trocadas.

Um core que passa só no `GFSbox` pode estar inteiro errado.

### Divisão de responsabilidade, registrada nos testbenches

Importa porque o firmware vai precisar fazer a mesma coisa:

- **`aes_core` faz ECB.** O encadeamento de CBC é do chamador — o testbench
  faz o XOR com o IV do lado de fora.
- **`sha256_core` recebe blocos de 512 bits já preenchidos.** O padding
  (FIPS 180-4) é do chamador — aqui, `scripts/mkvectors.py`; no dispositivo,
  o firmware.

Testar o core com o padding embutido misturaria duas coisas que falham por
motivos diferentes.

### Ferramentas novas

| Script | O que faz |
|---|---|
| `scripts/fetch-vectors.sh` | baixa das fontes oficiais, confere hash, extrai |
| `scripts/mkvectors.py` | converte `.rsp` → hex para `$readmemh`, e emite `counts.vh` |

`mkvectors.py` **não calcula nada**: chave, entrada e saída esperada são
copiadas literalmente do arquivo do NIST. A única coisa derivada é o padding
do SHA, e é deliberado.

O `counts.vh` existe para o testbench não hardcodar o número de vetores —
um número desatualizado lá faria o teste rodar sobre lixo em silêncio.

`scripts/sim.sh` agora regenera os vetores antes de cada rodada e compila os
cores de cripto junto.

### Bug que o próprio teste encontrou

`tb_sha256_kat` reprovou com sintoma característico: digests **corretos, mas
deslocados de um** — a mensagem 1 devolvia o digest da 0.

Causa: esperar apenas `ready` alto depois do comando termina de imediato,
porque o core ainda não baixou `ready`. Lê-se o resultado da operação
anterior.

Correção: esperar a operação **começar** (`ready` cair) e só então
**terminar** (`ready` subir).

O `tb_aes_kat` passava com o handshake fraco, por sorte de temporização.
Recebeu a mesma correção e os 1620 vetores foram reconfirmados. Teste que
passa por sorte é dívida, não aprovação.

---

## O que falta, na ordem

### 1. CFS — AES e SHA como coprocessadores

O `neorv32_cfs.vhd` é um template feito para ser substituído. A receita está
em `doc/submodulos.md` e **não exige patch nem tocar no submódulo**: filtra
o arquivo do upstream da lista e adiciona o nosso na mesma biblioteca.

Em `scripts/build.tcl`, depois de montar `$neorv32_files`:

```tcl
set neorv32_files [lsearch -all -inline -not $neorv32_files \
                   $neorv32/rtl/core/neorv32_cfs.vhd]
add_files rtl/crypto/neorv32_cfs.vhd
set_property library neorv32 [get_files rtl/crypto/neorv32_cfs.vhd]
```

O mesmo em `scripts/sim.sh`, filtrando antes do `xvhdl -work neorv32`.

Entidade a respeitar (de `third_party/neorv32/rtl/core/neorv32_cfs.vhd`):

```vhdl
entity neorv32_cfs is
  port (
    clk_i     : in  std_ulogic;
    rstn_i    : in  std_ulogic;
    bus_req_i : in  bus_req_t;
    bus_rsp_o : out bus_rsp_t;
    irq_o     : out std_ulogic;
    cfs_in_i  : in  std_ulogic_vector(255 downto 0);
    cfs_out_o : out std_ulogic_vector(255 downto 0)
  );
```

Lembrar de ligar `IO_CFS_EN => true` em `rtl/soc/neorv32_wrapper.vhd`.

**`GET_DNA` se resolve aqui.** Ele responde `STATUS_NOT_IMPLEMENTED` desde a
Fase 1 porque o `DNA_PORT` é primitiva Xilinx e precisa de um caminho até a
CPU — e o XBUS está desligado por decisão de segurança. Um registrador no
CFS é esse caminho.

**Atenção ao orçamento:** a folga de timing está em **+0,637 ns** (Fmax ≈
107 MHz). Os cores entram como datapath separado e não alongam o caminho
crítico atual, que está dentro da CPU, mas adicionam congestionamento — e
roteamento já é 45% do atraso. As alavancas, em ordem, estão em
`doc/fase1-notas.md`.

### 2. neoTRNG e os health tests

`IO_TRNG_EN => true` no wrapper. **Manter `IO_TRNG_NUM_RO` pequeno** — meia
dúzia de anéis. Centenas geram calor e ruído de alimentação localizados sem
ganho de entropia (`PLANO.md` §3).

RCT e APT em firmware, sobre a fonte bruta, conforme SP 800-90B. Falha em
qualquer um → `TAMPERED`, DRBG parado, LED vermelho.

É o conteúdo real da fase: esses testes são boa parte do motivo de uma
avaliação de módulo criptográfico levar meses.

### 3. CTR_DRBG em firmware

AES-256, resemeadura por política. Os vetores já estão em
`vectors/drbg/CTR_DRBG_AES256.rsp` — falta o conversor em `mkvectors.py` e o
KAT correspondente.

### 4. POST e comandos

KAT de AES, SHA, HMAC e DRBG no boot, **antes** de aceitar qualquer comando.
Falhou um vetor → o dispositivo não entra em operação.

Comandos `0x10 AES_ENC` · `0x11 AES_DEC` · `0x12 SHA256` · `0x13 HMAC` ·
`0x14 RANDOM` · `0x15 SELFTEST`.

Cada um passa pelo checklist do `CLAUDE.md` antes de ser escrito — em
especial: *o que vaza se for chamado em laço com entradas escolhidas?*

### Critérios de aceitação da fase (`PLANO.md` §3)

- [x] KAT de AES e SHA passam em simulação
- [ ] KAT passam também no POST
- [ ] `RANDOM` de 1 MB passa em `ent` e `dieharder -a` (sanidade, não validação)
- [ ] Forçar falha artificial no RCT leva o dispositivo a `TAMPERED`
- [ ] Utilização e timing arquivados

---

## Retomando o trabalho

```bash
git submodule update --init --recursive   # agora são três submódulos
source /opt/AMD/2026.1/Vivado/settings64.sh

./scripts/fetch-vectors.sh --check        # vetores íntegros?
make -C fw image
./scripts/sim.sh                          # 7 testbenches devem passar
```

**A placa não guarda nada.** A gravação da Fase 1 foi em RAM de configuração
(volátil) e se perdeu no desligamento. Para voltar ao ponto:

```bash
make -C fw image
vivado -mode batch -source scripts/build.tcl
./scripts/program.sh
python3 host/hsmtool.py ping
```

Se `--detect` do JTAG ficar intermitente, olhar o número do Device em
`lsusb` antes de suspeitar do bitstream: número mudando é conexão física
re-enumerando.

E lembrar que existem **duas** `/dev/ttyUSB*` com o gravador ligado — o
`hsmtool` escolhe por VID:PID, mas `--port` na mão pode acertar o cabo
errado.
