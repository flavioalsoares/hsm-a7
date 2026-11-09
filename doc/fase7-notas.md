# Fase 7: criptografia assimétrica

A teoria — RSA, exponenciação, produto de Montgomery, FIOS, tempo constante,
PKCS#1 v1.5 — está no manual, seção 32. Aqui ficam as peças, as medidas e o que
falta.

## Estado

| Frente | Situação |
|---|---|
| Produto de Montgomery (`rtl/crypto/rsa_mont.v`) | pronto, no CFS |
| Registradores no CFS | prontos |
| Exponenciação pública no firmware (`fw/src/rsa.c`) | pronta |
| KAT de RSA no POST | pronto |
| `R4` — verificar assinatura, porta host | pronto |
| Chave privada em key block (`S0`/`R`/`S`) | pronta |
| Assinatura com CRT e escada de Montgomery, verificada antes de sair | pronta |
| Geração de chave (FIPS 186-5, A.1.3) | pronta |
| `R0` gerar chave e `R2` assinar, porta host | prontos |
| P-256 | não começado |

✅ **Validado em hardware 2026-11-08.** `post` com os nove testes verdes, `RSA-2048`
entre eles, e `hsmhost.py rsa-cavp`: os 10 vetores SHA-256 do CAVP aceitos, e cada um
recusado com um bit trocado na assinatura. A LMK sobreviveu à gravação.

✅ **Metade privada validada em hardware 2026-11-09.** `post` com os nove testes
verdes. `hsmhost.py rsa-confere` gerou três chaves RSA-2048 na placa, em 24,1 s,
33,6 s e 20,9 s. O Python conferiu as três assinaturas `R2` de cada chave, e o `R4`
as aceitou. A LMK sobreviveu à gravação.

## Produto de Montgomery

Um comando calcula `dst = a * b * R^-1 mod N`, com `R = 2^(16 * len)`. O firmware
dirige a exponenciação: a política fica em C, e o que custa ciclo fica no hardware.

- Algoritmo FIOS, limbs de 16 bits, dois multiplicadores.
- 8 registradores de 128 limbs numa RAMB18, com módulo e acumulador em memória
  distribuída.
- `len` vai de 1 a 128, então o mesmo core serve para 2048 bits e para as metades de
  1024 bits do CRT.

⚠ **O tempo de um produto só depende de `len`.** A subtração final de N sempre
acontece, e um mux escolhe entre `T` e `T - N` na gravação. `tb_rsa_mont` cobra isso.
Não trocar por um desvio condicional: seria o ataque de temporização da seção 16.1 do
manual.

⚠ **O módulo é só de escrita.** Com CRT, ele é um primo da chave privada.

| Medida | Valor |
|---|---|
| Produto de 2048 bits | 18 433 ciclos, 184 µs a 100 MHz |
| Produto de 1024 bits | 5 121 ciclos, 51 µs |
| Core isolado | 500 LUTs, 165 FF, 4 DSP, 0,5 BRAM, folga +2,07 ns |

## Registradores no CFS

Página `0x200` do CFS. O bit 9 do endereço separa o RSA do resto do mapa.

| Endereço | Nome | Acesso | Conteúdo |
|---|---|---|---|
| `0x200` | `RSA_CTRL` | w | `[0]` START, `[6:4]` DST, `[10:8]` A, `[14:12]` B, `[23:16]` LEN |
| `0x204` | `RSA_N0P` | w | `-N^-1 mod 2^16` |
| `0x208` | `RSA_STATUS` | r | `[0]` BUSY |
| `0x20C` | `RSA_ADDR` | w | janela: `[10]` módulo, `[9:7]` registrador, `[6:0]` limb |
| `0x210` | `RSA_DATA` | rw | limb na janela; o endereço anda sozinho |

O `WIPE` global do CFS também apaga as memórias do core, e interrompe um produto em
curso.

## Firmware

`fw/src/rsa.c`:

- `rsa_publica(n, e, s, out)` — `s^e mod n`. Calcula `n'` por Newton e `R² mod n`
  partindo de `2R mod n` com 11 quadrados (`2^(2^11) = R`). Recusa `n` par, `n` sem o
  bit alto, `e` par ou menor que 3, e `s ≥ n`.
- `rsa_verifica(n, e, digest, s)` — PKCS#1 v1.5 com SHA-256. Monta o `EM` esperado e
  compara inteiro, acumulando diferenças: 1 confere, 0 não confere, -1 parâmetro
  inválido.

- `rsa_crt_assina(chave, digest, sig)` — assinatura PKCS#1 v1.5 por CRT. Devolve 0,
  -1 (falha) ou -2 (a verificação reprovou).
- `rsa_gera(chave, n)` — gera um par de chaves. `rsa_primo_provavel(w)` expõe o
  Miller-Rabin para o firmware de teste.

⚠ **A exponenciação pública desvia pelos bits de `e`**, porque `e` é público. A
operação privada usa a escada de Montgomery: cada bit custa um produto e um quadrado,
e o bit só escolhe os registradores, por máscara.

## Assinatura com CRT

A teoria está no manual, seção 32. As contas, todas no coprocessador:

1. `em mod p`: `em = hi·R + lo`, com `R = 2^1024`. A forma de Montgomery de `em` é
   `Mont(hi, R³) + Mont(lo, R²) mod p`. Não há divisão.
2. `sp = em^dp mod p` e `sq = em^dq mod q`, cada um pela escada, com 1024 bits de
   expoente.
3. `h = qinv·(sp − sq) mod p`.
4. `s = sq + h·q`. O produto inteiro `h·q` usa o módulo `M = 2^2048 − 1`: como
   `R ≡ 1 mod M`, o produto de Montgomery dá o produto comum. O mesmo truque calcula
   `n = p·q`.
5. `s^e mod n` tem de dar o `em`. Se não der, nada sai, o erro grave fica marcado e
   o host recebe `91`.

⚠ **O passo 5 é a contramedida do ataque Bellcore** (manual, 17.1). Uma assinatura
CRT errada fatora `n`. O passo 5 também pega erro de software.

⚠ **`metade()` usa `g_a` e `g_b` como rascunho.** Um valor que precisa sobreviver a
uma chamada de `metade()` fica em `g_sq`.

⚠ **Os rascunhos são estáticos e apagados no fim de toda assinatura**, junto com o
coprocessador (`hsm_cfs_wipe`). A pilha não comporta 1 KB de buffers.

## Geração de chave

FIPS 186-5, Apêndice A.1.3, primos prováveis:

- Candidato de 1024 bits do DRBG, com os dois bits altos e o bit baixo ligados.
- Divisão por todo ímpar menor que 1024. Elimina cerca de 84% dos candidatos sem
  exponenciação.
- `(p − 1)` não pode ser múltiplo de `e`.
- Miller-Rabin com 5 rodadas (Tabela B.1, erro de 2^-112). A base é sorteada e
  recusada se for ≤ 1 ou ≥ w − 1.
- `|p − q| > 2^924`.
- Limites de tentativas: 5·nlen para `p` e 10·nlen para `q`.
- `e = 65537`. `dp` e `dq` saem de um inverso de `e` com números pequenos;
  `qinv = q^(p−2) mod p`, pela escada.
- Teste de consistência (PCT): o dispositivo assina e verifica antes de entregar o
  par.

⚠ **O tempo da busca varia**, porque um candidato composto é descartado assim que se
revela. O tempo não diz nada sobre o primo aceito: cada candidato é sorteado de novo.

| Medida na placa | Valor |
|---|---|
| Geração de um par | 21 s a 34 s (três amostras) |

## A chave privada no key block

Key block X9.143 com uso `S0`, algoritmo `R` e modo `S`. **O conteúdo tem layout
próprio**, por decisão do usuário (2026-11-08):

| Campo | Bytes |
|---|---|
| `e` | 4 |
| `p` | 128 |
| `q` | 128 |
| `dp` | 128 |
| `dq` | 128 |
| `qinv` | 128 |

São 644 bytes de chave, 656 de corpo e 1360 caracteres de bloco. O `n` não entra:
o dispositivo o recalcula. Este layout é um desvio registrado. A norma não fixa como
representar uma chave RSA dentro do bloco.

⚠ **Os dois parsers mudaram juntos** (`fw/src/tr31.c`, `host/tr31.py`). Algoritmo
`R` exige uso `S0`, modo `S` e 644 bytes. Algoritmo `A` continua com até 32 bytes.

## Os comandos

| Pedido | Resposta | Campos do pedido | Campos da resposta | Log |
|---|---|---|---|---|
| `R0` gerar par RSA | `R1` | exportabilidade(1) | key block · n(512) · e(8) | sim |
| `R2` assinar | `R3` | key block · digest(64) | S(512) | sim |
| `R4` verificar assinatura | `R5` | n(512) · e(8) · digest(64) · S(512) | — | sim |

Todos em `OPERATIONAL`, sem dual control. Os números vão em hex.

- **`R0`**: a chave privada sai só como key block sob a LMK. O `n` e o `e` saem em
  claro, porque são públicos. Erros: `16` exportabilidade inválida, `90` falha
  interna, `91` o PCT reprovou.
- **`R2`**: erros `10` bloco inválido, `11` bloco de outro tipo de chave, `91` a
  verificação reprovou.
- **`R4`**: erro `00` confere, `01` não confere, `16` parâmetro inválido. Só dados
  públicos entram, e sai um bit.

`hsmhost.py` (ver `doc/codigo-host.md`):

- `rsa-gen`, `rsa-sign BLOCO DIGEST` e `rsa-verify N E DIGEST S` mandam um pedido.
- `rsa-confere` gera pares com `R0`, assina com `R2`, confere no Python e no `R4`.
- `rsa-cavp` roda os 10 vetores do CAVP no `R4`. Com `--lmk`, também assina com a
  chave do KeyGen do CAVP pelo `R2`.

⚠ **O `R0` espera até 120 s.** A ponte (`host/hsm_ponte.py`) e o `hsmhost.py`
esperam esse tempo pelos dois primeiros bytes da resposta.

## O que mudou em volta

- **Limite de mensagem: 2048 bytes** (`CMD_MAX_PAYLOAD`, e `MAX_PAYLOAD` no
  `hsmtool.py`). Um `R4` passa de 1100 caracteres.
- **`SELFTEST` devolve a máscara em dois bytes**, little-endian. O RSA é o bit
  `0x100`, o nono — o byte único da fase 3 não comportava. O `typedef` em
  `fw/include/kat.h` quebra o build se um teste novo não couber.
- **POST: 28,27 ms**, contra 10,19 na fase 6. São duas exponenciações com o `e` do
  vetor do CAVP (`0x260445`, 22 bits): a assinatura válida tem de conferir e a
  adulterada tem de ser recusada.
- **Firmware:** 30 052 bytes de código (IMEM de 32 KB, 92%) e 13 216 de dados (DMEM
  de 16 KB). O pico de pilha medido é cerca de 1 KB. Sobram 2 716 bytes de IMEM.
- **Mensagem do key block grande**: o `le_bloco` aceita até 1360 caracteres.

## Recursos e timing

Build completo, com o RSA dentro do SoC. Arquivado em `utilization_fase7.txt` e
`timing_fase7.txt`.

| | Fase 6 | Fase 7 |
|---|---|---|
| Folga | +0,471 ns | +0,273 ns |
| LUTs | 7699 | 8070 |
| FF | 7698 | 7915 |
| BRAM | 13 | 13,5 |
| DSP | 0 | 4 |

Zero critical warnings.

## Testes

| Testbench | O que prova | Tempo |
|---|---|---|
| `tb_rsa_mont` | 44 produtos contra inteiros do Python, com `len` de 128, 64, 2 e 1, incluindo 0, 1, N-1 e R mod N; ciclos iguais em todo produto de mesmo `len`; `S^e mod n` dos 10 vetores do CAVP; `wipe` apaga as três memórias | < 1 min |
| `tb_cfs` | o core pelo mapa de registradores | |
| `tb_rsa` | o `R4` pela UART, com o firmware real: recusado antes da cerimônia (`20`), assinatura do CAVP aceita (`00`), adulterada recusada (`01`), pedido curto (`22`). O `R2` com a chave do KeyGen do CAVP assina por CRT e dá a assinatura esperada; o bloco adulterado dá `10`, e um bloco de chave AES dá `11` | 2 h 18 |
| `tb_rsa_mr` | o Miller-Rabin no **firmware de teste** (`make HSM_TESTE_MR=1`): aceita o primo e recusa os dois compostos do KAT de primalidade do CAVP | 2 h 24 |

`tb_rsa_mont` reprova com o core sabotado: sem a subtração, sem o limb alto na
comparação e sem o carry de fim de linha.

Suíte completa em 2026-11-09: 25 testbenches passam.

⚠ **A geração de ponta a ponta não roda na simulação**: a busca de primos leva
segundos na placa, e horas de simulação por segundo. Ela é provada por partes: o
Miller-Rabin no `tb_rsa_mr`, a assinatura com uma chave oficial no `tb_rsa`. O par
completo é provado na placa pelo `rsa-confere`.

⚠ **`sim.sh` escolhe o firmware pela diretiva `sim-firmware:`** no testbench. Trocar
de variante recompila tudo (`make -B`) e anota a variante em `fw/.variante`. Depois de
um testbench de variante, o firmware em `fw/` é o de teste: recompilar a produção
(`make -B -C fw image`) antes do build do Vivado.

⚠ **Nos testbenches, os botões ficam soltos e apertados por 1 ms.** Depois de cada
resposta o firmware apaga os buffers de 2048 bytes, e com 100 µs ele não via os
botões soltos — o dual control recusava o segundo componente. Um gesto humano dura
centenas de vezes isso.

⚠ **`tb_soc_silent` observa 32 ms e `tb_post_tamper` tem 80 ms de prazo.** As duas
janelas existem para acusar o POST quando ele cresce. Crescendo de novo, elas
reprovam, e é para isso que existem.

⚠ **O KAT do POST cobre só `S^e`, com `e` de 22 bits.** A assinatura não está no
POST. Pô-la custaria cerca de 0,2 s por boot. Fica para decisão do usuário.

⚠ **A assinatura esperada do `R2` no `tb_rsa` é conta do Python.** A chave é oficial
(KeyGen do CAVP), mas o CAVP não publica assinatura para ela. A verificação com `e`
confere a conta.

## Próximos passos

1. Rodar `hsmhost.py rsa-cavp --lmk` na placa. O comando precisa da LMK em hex.
2. Decidir se a assinatura entra no POST.
3. P-256.
