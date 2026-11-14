# Fase 7: criptografia assimétrica

A teoria — RSA, exponenciação, produto de Montgomery, FIOS, tempo constante,
PKCS#1 v1.5, curvas elípticas e ECDSA — está no manual, seção 30. Aqui ficam as
peças, as medidas e o que falta.

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
| ECDSA P-256 no firmware (`fw/src/ecc.c`), no mesmo coprocessador | pronto |
| Chave de ECDSA em key block (`S0`/`E`/`S`) | pronta |
| `E0` gerar par, `E2` assinar e `E4` verificar, porta host | prontos |
| Autotestes de primeiro uso: assinatura RSA e ECDSA | prontos |

✅ **Validado em hardware 2026-11-08.** `post` com os nove testes verdes, `RSA-2048`
entre eles, e `hsmhost.py rsa-cavp`: os 10 vetores SHA-256 do CAVP aceitos, e cada um
recusado com um bit trocado na assinatura. A LMK sobreviveu à gravação.

✅ **Metade privada validada em hardware 2026-11-09.** `post` com os nove testes
verdes. `hsmhost.py rsa-confere` gerou três chaves RSA-2048 na placa, em 24,1 s,
33,6 s e 20,9 s. O Python conferiu as três assinaturas `R2` de cada chave, e o `R4`
as aceitou. A LMK sobreviveu à gravação.

✅ **ECDSA validado em hardware 2026-11-14.** `hsmhost.py ecdsa-cavp`: os 15 vetores
de SigVer e os 12 de PKV do CAVP com a resposta certa. `ecdsa-confere`: 20 pares
gerados na placa e 60 assinaturas, conferidas pelo Python e pelo `E4`. O `E0`
responde em 0,53 s. `rsa-cavp` e `rsa-confere` passam com o firmware novo, e o
`post` mostra os dois autotestes de primeiro uso como pendentes até o primeiro uso.

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

A teoria está no manual, seção 30. As contas, todas no coprocessador:

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
| Geração de um par | 13 s a 44 s (seis amostras) |

## ECDSA P-256

O ECDSA usa o mesmo coprocessador do RSA, com `len` = 16 limbs (256 bits). Não há
RTL novo. O firmware (`fw/src/ecc.c`) dirige a multiplicação de ponto e as contas
da assinatura.

- **Curva:** P-256 (FIPS 186-4, D.1.2.3). Os parâmetros estão em `ecc.c`.
- **Corpo:** os elementos ficam em C, em 8 palavras de 32 bits, na representação
  de Montgomery. Cada produto manda os dois operandos ao core e lê o resultado.
  Soma, subtração e comparação são feitas em C, sem desvio pelo valor.
- **Multiplicação de ponto:** escada de Montgomery em coordenadas (X, Y) com Z
  comum (Rivain, 2011, algoritmo 9). A organização do código segue a da biblioteca
  micro-ecc. São 14 produtos e 18 somas ou subtrações por bit, 256 passos para todo
  escalar.
- **Inverso:** pelo pequeno teorema de Fermat, com `mont_escada()`, no core.
- **Contas módulo n** (`k⁻¹`, `r·d`, `e/s`, `r/s`): no core, com o módulo trocado
  para `n`.

| Medida | Valor |
|---|---|
| Produtos de Montgomery por multiplicação de ponto | 4 132 |
| Limbs trocados com o core por multiplicação de ponto | 152 672 |
| Multiplicações de ponto por comando | `E0`: 4 · `E2`: 3 · `E4`: 4 |
| Tempo de uma multiplicação de ponto | 124 ms (simulação); `E0` na placa: 0,53 s |
| Autoteste de primeiro uso do ECDSA | 5 multiplicações de ponto, cerca de 0,6 s, uma vez por boot |

⚠ **A escada não serve para os escalares 1, n−1 e n−2.** Com eles, um ponto
intermediário é o ponto no infinito, que as fórmulas não representam.
`ponto_mult()` trata os três casos à parte: `P`, `−P` e `−2P`. Na verificação,
quem monta a assinatura escolhe os escalares, e sem esse tratamento a resposta
sairia errada. `host/test_ecc.py` cobra os três casos.

⚠ **A soma final da verificação trata as exceções**: `u1 = 0`, `P1 = P2` (dobra) e
`P1 = −P2` (infinito, assinatura inválida). São raras com assinaturas honestas, e
fáceis de produzir para quem escolhe a entrada.

⚠ **O `k` de cada assinatura sai do DRBG**, por amostragem com rejeição
(FIPS 186-5, A.3.2). A chave privada `d` também (A.2.2). `ecdsa_assina_k()`
recebe o `k` de quem chama e existe só para o KAT do CAVP. Um `k` repetido ou
previsível entrega a chave privada.

⚠ **A assinatura é verificada com `Q` antes de sair**, como a do RSA é verificada
com `e`. Reprovou: `91`, nada sai, erro grave marcado.

⚠ **A chave pública é validada em toda verificação**: coordenadas menores que `p`
e ponto na curva. A curva tem cofator 1, então isso basta.

`mont.c` e `bn.c` saíram do `rsa.c`: o preparo do módulo, a escada de
exponenciação e a aritmética de bytes, que o RSA e o ECDSA usam.

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

A chave de ECDSA usa o algoritmo `E`, com o mesmo uso `S0` e o mesmo modo `S`. O
layout também é próprio:

| Campo | Bytes |
|---|---|
| `d` | 32 |
| `Qx` | 32 |
| `Qy` | 32 |

São 96 bytes de chave, 112 de corpo e 272 caracteres de bloco. A chave pública vai
junto para a assinatura ser verificada antes de sair, sem recalcular `Q = d·G` a
cada comando.

⚠ **Os dois parsers mudaram juntos** (`fw/src/tr31.c`, `host/tr31.py`). Algoritmo
`R` exige uso `S0`, modo `S` e 644 bytes. Algoritmo `E` exige uso `S0`, modo `S` e
96 bytes. Algoritmo `A` continua com até 32 bytes.

⚠ **A chave RSA e a de ECDSA ocupam a mesma área do key store** (`g_rsa`), uma por
comando. `keystore_rsa_abre()` recusa um bloco `E`, e `keystore_ec_abre()` recusa
um bloco `R`, as duas com `-3` (erro `11` no comando).

## Os comandos

| Pedido | Resposta | Campos do pedido | Campos da resposta | Log |
|---|---|---|---|---|
| `R0` gerar par RSA | `R1` | exportabilidade(1) | key block · n(512) · e(8) | sim |
| `R2` assinar | `R3` | key block · digest(64) | S(512) | sim |
| `R4` verificar assinatura | `R5` | n(512) · e(8) · digest(64) · S(512) | — | sim |

| `E0` gerar par P-256 | `E1` | exportabilidade(1) | key block · Qx(64) · Qy(64) | sim |
| `E2` assinar | `E3` | key block · digest(64) | r(64) · s(64) | sim |
| `E4` verificar assinatura | `E5` | Qx(64) · Qy(64) · digest(64) · r(64) · s(64) | — | sim |

Todos em `OPERATIONAL`, sem dual control. Os números vão em hex.

- **`R0`**: a chave privada sai só como key block sob a LMK. O `n` e o `e` saem em
  claro, porque são públicos. Erros: `16` exportabilidade inválida, `90` falha
  interna, `91` o PCT reprovou.
- **`R2`**: erros `10` bloco inválido, `11` bloco de outro tipo de chave, `91` a
  verificação reprovou.
- **`R4`**: erro `00` confere, `01` não confere, `16` parâmetro inválido, `91` as
  duas verificações discordaram (erro grave marcado). Só dados públicos entram, e
  sai um bit.

- **`E0`**: erros `16` exportabilidade inválida, `90` falha interna, `91` o par novo
  não assinou e verificou.
- **`E2`**: erros `10` bloco inválido, `11` bloco de outro tipo de chave, `91` a
  verificação reprovou.
- **`E4`**: `00` confere, `01` não confere, `16` a chave pública não é um ponto da
  curva, `91` as duas verificações discordaram. Como o `R4`, verifica duas vezes.

⚠ **O `R4` verifica DUAS vezes** (2026-11-09), como tudo o que sai ao host desde a
fase 6. Um bit é o alvo mais fácil de uma falha induzida: um glitch na comparação
final trocaria "não confere" por "confere". Só o acordo das duas contas vale; o
custo é uma exponenciação pública a mais por pedido.

⚠ **O `WIPE` apaga também a interface do RSA** (2026-11-09): `rsa_wdata` (o último
limb escrito pela CPU, que no CRT é um pedaço da chave), `rsa_n0p` (−p⁻¹ mod 2¹⁶,
que vem de um primo) e o `n0p` dentro de `rsa_mont.v`. `tb_cfs` e `tb_rsa_mont`
cobram isso.

`hsmhost.py` (ver `doc/codigo-host.md`):

- `rsa-gen`, `rsa-sign BLOCO DIGEST` e `rsa-verify N E DIGEST S` mandam um pedido.
- `rsa-confere` gera pares com `R0`, assina com `R2`, confere no Python e no `R4`.
- `rsa-cavp` roda os 10 vetores do CAVP no `R4`. Com `--lmk`, também assina com a
  chave do KeyGen do CAVP pelo `R2`.

- `ecdsa-gen`, `ecdsa-sign BLOCO DIGEST` e `ecdsa-verify QX QY DIGEST R S` mandam
  um pedido.
- `ecdsa-confere` gera pares com `E0`, assina com `E2`, confere no Python e no
  `E4`, e cobra que o `r` não se repita.
- `ecdsa-cavp` roda os vetores de SigVer e de PKV do CAVP no `E4`. Com `--lmk`,
  também assina com chaves do SigGen do CAVP pelo `E2`.

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
- **IMEM de 32 para 64 KB** (decisão do usuário, 2026-11-13). Com o RSA sobravam
  2 716 bytes, e o ECDSA não cabia.
- **Firmware:** 37 668 bytes de código (IMEM de 64 KB, 57%) e 13 964 de dados (DMEM
  de 16 KB). Sobram 2 420 bytes para a pilha; o caminho mais fundo usa cerca de
  1,1 KB.
- **Autotestes de primeiro uso** (decisão do usuário, 2026-11-13). O KAT da
  assinatura RSA e o do ECDSA não rodam no boot. Cada um roda antes do primeiro
  uso do algoritmo depois do boot: no primeiro `R0` ou `R2`, e no primeiro `E0`,
  `E2` ou `E4`. A FIPS 140-3 permite isso (autoteste condicional de algoritmo).
  Reprovou: a BRAM é apagada, o dispositivo vai para `TAMPERED`, e o comando
  responde `91`. O `SELFTEST` não roda esses dois testes; os bits `0x200` e `0x400`
  da máscara só aparecem se um deles já reprovou neste boot.
- **Mensagem do key block grande**: o `le_bloco` aceita até 1360 caracteres.

## Recursos e timing

Build completo, com o RSA dentro do SoC e a IMEM de 64 KB. Arquivado em
`utilization_fase7.txt` e `timing_fase7.txt`.

| | Fase 6 | Fase 7, RSA | Fase 7, com a IMEM de 64 KB |
|---|---|---|---|
| Folga | +0,471 ns | +0,337 ns | +0,369 ns |
| LUTs | 7699 | 8079 | 8078 |
| FF | 7698 | 7915 | 7915 |
| BRAM | 13 | 13,5 | 21,5 |
| DSP | 0 | 4 | 4 |

O ECDSA não tem RTL: a diferença da última coluna é só a IMEM, que custa 8 Block
RAMs. O chip tem 50.

Zero critical warnings.

## Testes

| Testbench | O que prova | Tempo |
|---|---|---|
| `tb_rsa_mont` | 44 produtos contra inteiros do Python, com `len` de 128, 64, 2 e 1, incluindo 0, 1, N-1 e R mod N; ciclos iguais em todo produto de mesmo `len`; `S^e mod n` dos 10 vetores do CAVP; `wipe` apaga as três memórias | < 1 min |
| `tb_cfs` | o core pelo mapa de registradores | |
| `tb_rsa` | o `R4` pela UART, com o firmware real: recusado antes da cerimônia (`20`), assinatura do CAVP aceita (`00`), adulterada recusada (`01`), pedido curto (`22`). O `R2` com a chave do KeyGen do CAVP assina por CRT e dá a assinatura esperada; o bloco adulterado dá `10`, e um bloco de chave AES dá `11`. O primeiro `R2` roda o autoteste de primeiro uso da assinatura RSA | 3 h 27 |
| `tb_ecdsa` | o `E4` pela UART, com o firmware real: recusado antes da cerimônia (`20`), um vetor "P" do SigVer do CAVP aceito (`00`), um vetor "S changed" recusado (`01`), chave pública fora da curva (`16`), pedido curto (`22`). O `E2` assina com uma chave do SigGen do CAVP, e o `E4` aceita essa assinatura; o bloco adulterado dá `10`, e um bloco de chave AES dá `11`. O primeiro `E4` roda o autoteste de primeiro uso | 8 h 46 |
| `host/test_ecc.py` | **no PC**: o `ecc.c` do firmware, compilado com `gcc` e ligado a um modelo em C do coprocessador (`fw/teste/ecc_nativo.c`). Os 52 vetores de P-256 do CAVP (KeyPair, PKV, SigGen com o `k` do vetor, SigVer), os escalares de borda, os casos de exceção da verificação e a conferência cruzada com a biblioteca `cryptography` | 4 s |
| `tb_rsa_mr` | o Miller-Rabin no **firmware de teste** (`make HSM_TESTE_MR=1`): aceita o primo e recusa os dois compostos do KAT de primalidade do CAVP | 2 h 24 |

`tb_rsa_mont` reprova com o core sabotado: sem a subtração, sem o limb alto na
comparação e sem o carry de fim de linha.

Suíte completa em 2026-11-14: 26 testbenches passam, em 11 h 07 com 3 por vez. O
`tb_ecdsa` é o mais lento (8 h 46, 2,65 s simulados), seguido do `tb_tamper` (3 h 46)
e do `tb_rsa` (3 h 27).

⚠ **`host/test_ecc.py` não prova a integração com o hardware.** Ele roda o `ecc.c`
contra um modelo em C do coprocessador. Quem prova o caminho real (CPU, CFS e core)
é o `tb_ecdsa`, e depois a placa.

⚠ **A geração de ponta a ponta não roda na simulação**: a busca de primos leva
segundos na placa, e horas de simulação por segundo. Ela é provada por partes: o
Miller-Rabin no `tb_rsa_mr`, a assinatura com uma chave oficial no `tb_rsa`. O par
completo é provado na placa pelo `rsa-confere`.

⚠ **`sim.sh` escolhe o firmware pela diretiva `sim-firmware:`** no testbench. Trocar
de variante recompila tudo (`make -B`) e anota a variante em `fw/.variante`. O
testbench de variante roda sozinho, e o `sim.sh` restaura a produção em seguida.

⚠ **A suíte roda 3 testbenches por vez** (`SIM_JOBS`), cada um em `build/sim/<tb>/`.
O histórico de durações fica em `build/sim/tempos.csv`, e a suíte começa pelos mais
longos.

⚠ **Nos testbenches, os botões ficam soltos e apertados por 1 ms.** Depois de cada
resposta o firmware apaga os buffers de 2048 bytes, e com 100 µs ele não via os
botões soltos — o dual control recusava o segundo componente. Um gesto humano dura
centenas de vezes isso.

⚠ **`tb_soc_silent` observa 32 ms e `tb_post_tamper` tem 80 ms de prazo.** As duas
janelas existem para acusar o POST quando ele cresce. Crescendo de novo, elas
reprovam, e é para isso que existem.

⚠ **Os dois autotestes de primeiro uso ficam fora do boot por causa da simulação.**
Cada 0,2 s de POST custa cerca de 31 min em cada testbench que liga o SoC.

| Autoteste | Vetor | O que cobra |
|---|---|---|
| Assinatura RSA | `SigGen15_186-3.txt` do CAVP | a assinatura por CRT é, byte a byte, o `S` do vetor |
| ECDSA | primeiro vetor de `SigGen_P256.txt` do CAVP | com o `k` do vetor, `r` e `s` são os do vetor; a verificação aceita essa assinatura e a recusa com um bit trocado |

⚠ **O CAVP dá `n`, `e` e `d` para o RSA, e a assinatura por CRT precisa de `p` e
`q`.** `scripts/mkkat.py` fatora `n` com `e·d − 1` e para se `p·q` não for o `n` do
vetor ou se a assinatura por CRT não for o `S` do vetor.

⚠ **A assinatura esperada do `R2` no `tb_rsa` é conta do Python.** A chave é oficial
(KeyGen do CAVP), mas o CAVP não publica assinatura para ela. A verificação com `e`
confere a conta.

## Próximos passos

1. Rodar `hsmhost.py rsa-cavp --lmk` e `hsmhost.py ecdsa-cavp --lmk` na placa. Os
   comandos precisam da LMK em hex.
