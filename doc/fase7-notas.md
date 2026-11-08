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
| Chave privada, geração, assinatura com CRT | não começadas |
| P-256 | não começado |

✅ **Validado em hardware 2026-11-08.** `post` com os nove testes verdes, `RSA-2048`
entre eles, e `hsmhost.py rsa-cavp`: os 10 vetores SHA-256 do CAVP aceitos, e cada um
recusado com um bit trocado na assinatura. A LMK sobreviveu à gravação.

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

⚠ **A exponenciação desvia pelos bits de `e`**, porque `e` é público. A operação
privada não pode desviar: vai precisar de escada de Montgomery.

⚠ **`rsa.c` só vê dados públicos, por enquanto.** Quando a chave privada entrar, ela
vem do key store e o módulo de cada metade do CRT é segredo.

## O comando `R4`

| Pedido | Resposta | Campos do pedido | Campos da resposta | Log |
|---|---|---|---|---|
| `R4` verificar assinatura RSA | `R5` | n(512) · e(8) · digest(64) · S(512) | — | sim |

Tudo em hex. Erro `00`: confere. `01`: não confere. `16`: parâmetro inválido. Em
`OPERATIONAL` apenas, sem dual control. Só dados públicos entram, e sai um bit.

`hsmhost.py rsa-verify N E DIGEST S` manda um pedido; `hsmhost.py rsa-cavp` roda os 10
vetores do CAVP, cada um também com um bit trocado.

## O que mudou em volta

- **Limite de mensagem: 2048 bytes** (`CMD_MAX_PAYLOAD`, e `MAX_PAYLOAD` no
  `hsmtool.py`). Um `R4` passa de 1100 caracteres.
- **`SELFTEST` devolve a máscara em dois bytes**, little-endian. O RSA é o bit
  `0x100`, o nono — o byte único da fase 3 não comportava. O `typedef` em
  `fw/include/kat.h` quebra o build se um teste novo não couber.
- **POST: 28,27 ms**, contra 10,19 na fase 6. São duas exponenciações com o `e` do
  vetor do CAVP (`0x260445`, 22 bits): a assinatura válida tem de conferir e a
  adulterada tem de ser recusada.
- **Firmware:** 25 868 bytes de código (IMEM de 32 KB) e 10 876 de dados (DMEM de
  16 KB).

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
| `tb_rsa` | o `R4` pela UART, com o firmware real: recusado antes da cerimônia (`20`), assinatura do CAVP aceita (`00`), adulterada recusada (`01`), pedido curto (`22`) | ~50 min |

`tb_rsa_mont` reprova com o core sabotado: sem a subtração, sem o limb alto na
comparação e sem o carry de fim de linha.

Suíte completa em 2026-11-08: 24 testbenches passam.

⚠ **Nos testbenches, os botões ficam soltos e apertados por 1 ms.** Depois de cada
resposta o firmware apaga os buffers de 2048 bytes, e com 100 µs ele não via os
botões soltos — o dual control recusava o segundo componente. Um gesto humano dura
centenas de vezes isso.

⚠ **`tb_soc_silent` observa 32 ms e `tb_post_tamper` tem 80 ms de prazo.** As duas
janelas existem para acusar o POST quando ele cresce. Crescendo de novo, elas
reprovam, e é para isso que existem.

⚠ **O KAT cobre `S^e`, com `e` de 22 bits.** A operação privada não foi exercitada
com um expoente de 2048 bits: o CAVP não publica `d` neste arquivo. E a referência
dos 44 produtos é Python, não vetor oficial.

## Próximos passos

1. Chave RSA privada como key block sob a LMK, mantida pelo host. Os dois parsers de
   X9.143 (`fw/src/tr31.c` e `host/tr31.py`) mudam juntos.
2. Geração de chave dentro da fronteira, com Miller-Rabin.
3. Assinatura com CRT e escada de Montgomery, em tempo constante.
4. Verificar antes de emitir (Bellcore, manual 17.1), mais a dupla execução da fase 6.
5. P-256.
