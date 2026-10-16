# O código do lado do host (Python)

Guia de leitura de `host/`, para quem quer entender como o computador conversa
com o HSM. Atualizado na fase 4 (2026-10-16).

```
host/
  hsmtool.py       a ferramenta de linha de comando: protocolo, transporte e um
                   subcomando para cada comando do dispositivo
  tr31.py          key block ANSI X9.143 (TR-31 versão D), segunda implementação
  test_hsmtool.py  testes do transporte, sem placa (pty + dispositivo falso)
  test_tr31.py     testes do key block, sem placa
  audit.py         placeholder; a leitura do log está em `hsmtool.py audit`
```

Dependências: `pyserial` para falar com a placa e `cryptography` para o
`tr31.py`. Nada mais.

---

## 1. A regra que organiza tudo: o host está FORA

O host fica **fora da fronteira criptográfica**. Ele nunca deveria ver chave
em claro: recebe handles, KCVs, criptogramas, key blocks embrulhados e o log.
Se um subcomando do `hsmtool` imprimir material de chave, o defeito está no
comando, não no script.

O projeto é um brinquedo de bancada, e há **três exceções conscientes**, todas
marcadas no código:

| Exceção | Por que existe |
|---|---|
| `lmk-load --random` e `comp-load --random` | geram o componente no host e o mostram na tela. Num HSM comercial cada custodiante traz o seu; aqui não há custodiante. |
| `keycycle --lmk` | precisa da LMK para que o Python **confira** o firmware com uma implementação independente. |
| `tr31.py` inteiro | sabe embrulhar e desembrulhar, e para isso recebe a chave que embrulha. Existe para validar o C, não para produção. |

---

## 2. `hsmtool.py`, de baixo para cima

O arquivo tem quatro camadas, nesta ordem.

### 2.1 Codec: montar e validar frames, sem porta serial

```
pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)
```

Tudo big-endian. `LEN` conta só `CMD`/`STATUS` + payload. O CRC32 cobre todos
os bytes menos os quatro dele, com o polinômio IEEE 802.3 refletido, que é
exatamente o `zlib.crc32`.

- `build_request(opcode, payload)` monta um pedido e recusa payload acima de
  512 bytes.
- `parse_response(frame)` valida comprimento e CRC e devolve
  `(status, payload)`. Levanta `CrcError` ou `ProtocolError`.

Essa camada não importa `serial`, e é de propósito: assim ela pode ser testada
sozinha. O `hsmtool.py selftest` a confere contra **vetores fixos**, bytes
que bateram com três implementações independentes (o firmware em C, o
testbench em Verilog e o `zlib`). Se os vetores fossem gerados pelo próprio
módulo, o teste só provaria que o código concorda consigo mesmo.

### 2.2 Transporte: a porta serial

- `default_port()` escolhe a porta **pelo VID:PID** do CP2102 (`10c4:ea60`),
  não pela ordem alfabética. Com o gravador ligado existem duas
  `/dev/ttyUSB*`, e a primeira costuma ser o FT232H do JTAG. Escolher pelo
  nome acerta o cabo errado e dá um timeout sem explicação.
- `HsmClient` abre a porta a 115200 baud. O dispositivo de produção é **mudo
  até ser perguntado**, então não há banner a descartar; mesmo assim a
  entrada é limpa uma vez, por causa de sobras de sessões interrompidas.
- `transact(opcode, payload)` envia, lê os 2 bytes de `LEN`, lê o resto e
  devolve `(status, payload)`. **Não limpa a entrada antes de enviar**: byte
  inesperado na linha é sintoma de dessincronização, e escondê-lo tornaria
  sem valor o teste de 10 000 pings.
- `command(...)` faz o mesmo, mas levanta `HsmError` se o status não for OK.
  Quase todos os subcomandos usam este.
- `resync()` espera mais que o timeout entre bytes do firmware (250 ms), para
  que **os dois lados** abandonem o frame parcial, e só então descarta a
  entrada.

### 2.3 Os subcomandos

Cada subcomando é uma função `cmd_<nome>(client, args)`, registrada no
dicionário `handlers` dentro de `main()`. Os grupos:

| Grupo | Subcomandos | Comandos do dispositivo |
|---|---|---|
| Identidade e diagnóstico | `ping`, `version`, `dna`, `bench`, `post` | `0x01`, `0x02`, `0x03`, `0x15` |
| Funções públicas | `sha256`, `random` | `0x12`, `0x14` |
| Cerimônia da LMK | `lmk-status`, `lmk-load`, `activate` | `0x21`, `0x20`, `0x26` |
| Chaves | `gen-key`, `export-key`, `import-key`, `key-info`, `delete-key`, `comp-load` | `0x22`–`0x25`, `0x2B`, `0x2C` |
| Uso de chave | `encrypt`, `decrypt`, `mac`, `mac-verify` | `0x27`–`0x2A` |
| Fase 4 | `audit` | `0x2D` |
| Destruição | `zeroize` | `0x2F` |
| Bancada | `keycycle`, `raw` | vários |

Pontos que valem uma leitura no código:

- **`_pede_dual_control()`** não autoriza nada. Ela só pede ao operador que
  segure os dois botões e tecle Enter. **O host não tem como provar dual
  control**: quem decide é o firmware, que lê os botões. Se eles não estiverem
  apertados quando o frame chegar, a resposta é `NOT_AUTHORIZED`, e essa
  recusa é a única prova de que o dual control existe de verdade.
- **`lmk-load --random`** usa `os.urandom` e não o `RANDOM` do dispositivo.
  Um componente gerado pelo próprio módulo que vai guardá-lo não é split
  knowledge: o módulo saberia os três.
- **`mac-verify`** não recebe a tag de volta. O dispositivo compara em tempo
  constante e devolve um bit, no status `MAC_INVALID`.
- **`audit`** pede o log em blocos de até 16 registros e segue o campo
  `continuar` até alcançar `proximo`. Um resultado `PENDENTE` é um comando
  que começou e não terminou. Os registros de boot (`BOOT`) mostram se o
  POST passou, se a flash respondeu e se o registro persistente foi
  restaurado.
- **`bench`** é o critério de aceitação da fase 1: 10 000 pings, nenhum erro,
  nenhum acima de 50 ms.

### 2.4 `keycycle`: o Python conferindo o C

É o teste mais importante que roda contra a placa. Com a LMK em mãos (só num
brinquedo), ele:

1. manda o dispositivo gerar uma chave e a exporta **N vezes**. O Python
   desembrulha cada bloco com o `tr31.py`, confere que a chave dentro tem o
   KCV do slot e que os N blocos são todos diferentes (o enchimento é
   aleatório; blocos repetidos denunciariam a mesma chave);
2. embrulha no Python N chaves que ele mesmo escolheu, importa no
   dispositivo e exige o KCV que o Python calculou;
3. troca um bit de cada bloco e exige recusa;
4. apaga o slot a cada volta, e por isso chega aos 100.

Sem a etapa 2, o acordo seria de mão única: o C poderia errar do mesmo jeito
nas duas direções e ainda concordar consigo mesmo.

O KCV do lado do host vem de `_kcv_local()`, com o AES da biblioteca
`cryptography`. Comparar o KCV do dispositivo com outro KCV do dispositivo não
provaria nada.

---

## 3. `tr31.py`: a segunda implementação do key block

O formato X9.143 versão D está escrito **duas vezes**: em C, em
`fw/src/tr31.c`, dentro da fronteira, e aqui. A menor divergência na leitura
da norma aparece como MAC inválido, que é a forma mais barata de aprender um
formato binário.

```
cabeçalho(16 ASCII) || hex(corpo cifrado) || hex(MAC de 16 bytes)

corpo em claro = comprimento da chave em bits (2) || chave || enchimento aleatório
```

As funções, na ordem em que um bloco é feito:

- `deriva_subchaves(kbpk)` gera **KBEK** (cifra) e **KBAK** (MAC) por CMAC,
  com propósitos diferentes (`0x0000` e `0x0001`). Com a mesma chave para as
  duas funções, um oráculo de MAC seria um oráculo de cifra.
- `monta_cabecalho(...)` e `_valida_campos(...)` cuidam dos 16 caracteres do
  cabeçalho. ⚠ Os modos de uso aceitos têm de ser **os mesmos do C**; se só um
  lado aceitar um valor, um bloco legítimo é recusado de um lado e aceito do
  outro.
- `embrulha(kbpk, chave, ...)`: o MAC é calculado sobre **cabeçalho + corpo
  em claro**, e **o próprio MAC vira o IV** do AES-CBC que cifra o corpo.
- `desembrulha(kbpk, bloco)` decifra, recalcula o MAC e compara em tempo
  constante (`_iguais`). Em qualquer erro levanta **uma única** exceção,
  `Tr31Erro`; distinguir "MAC errado" de "enchimento errado" seria o oráculo
  de padding clássico.

A biblioteca `cryptography` é usada **de propósito**, em vez de reaproveitar
algo do firmware: se as duas implementações compartilhassem o AES,
concordariam num erro do AES sem nunca discordar.

---

## 4. Os testes que rodam sem placa

```bash
python3 host/hsmtool.py selftest    # codec: vetores fixos, CRC e LEN recusados
python3 host/test_hsmtool.py        # transporte
python3 host/test_tr31.py           # key block
```

- **`test_hsmtool.py`** liga o cliente a um **pty** e põe do outro lado um
  `FakeDevice`, um dispositivo mínimo em Python que responde certo ou com
  defeitos escolhidos: mudo, CRC errado ou frame cortado. Ele prova que o
  cliente se comporta quando a linha se comporta mal. **Não** prova acordo
  com o firmware; quem prova isso é o `tb_uart_frame`, que roda o firmware de
  verdade em simulação.
- **`test_tr31.py`** prova quatro coisas:
  1. um bloco de **terceiros** (procedência em `vectors/MANIFEST.txt`; não é
     do CAVP) desembrulha na chave certa;
  2. ida e volta;
  3. um bit trocado em **qualquer** das posições do bloco é recusado. É este
     teste que pega uma implementação que esqueceu de pôr o cabeçalho no MAC;
  4. KBEK ≠ KBAK.

---

## 5. Como acrescentar um subcomando

1. a constante `CMD_<NOME>`, copiando o valor de `fw/include/cmd.h`;
2. o nome do status novo em `STATUS_NAMES`, se houver;
3. `cmd_<nome>(client, args)`, conferindo o **comprimento** do payload de
   resposta antes de interpretá-lo;
4. o `sub.add_parser(...)` em `main()` e a entrada no dicionário `handlers`;
5. uma linha no docstring do topo do arquivo, que serve de ajuda rápida.

E a pergunta de sempre: **isto faz chave em claro aparecer aqui?** Se fizer, o
comando está errado.
