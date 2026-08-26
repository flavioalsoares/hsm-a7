# Documentação — roteiro de leitura

Este é um projeto **didático**: o objetivo é entender como um HSM funciona
construindo um de brinquedo.

> **Este dispositivo não é um HSM.** Não há PUF, malha antitamper, sensores
> físicos, RNG certificado nem validação FIPS/PCI. Nenhuma chave de produção
> entra aqui. O valor está em entender a arquitetura de dentro para fora.

## O manual

**[`hsm-a7-manual.pdf`](hsm-a7-manual.pdf)** — 62 páginas, o documento
principal. Fonte em [`manual/`](manual/), legível como Markdown; o PDF é
gerado por `./scripts/mkpdf.sh`.

| Parte | Assunto |
|---|---|
| **I — O que é um HSM** | O problema que resolve, modelo de ameaça, as três propriedades, onde HSMs são usados |
| **II — Arquitetura interna** | Fronteira criptográfica, hierarquia de chaves, cerimônia de LMK, key blocks TR-31, máquina de estados, aleatoriedade, self-test, zeroização, log, ciclo de vida |
| **III — Como HSMs são atacados** | Ataques de API (tabela de decimalização, confusão de tipo, PIN blocks), canais laterais, injeção de falha, ataques físicos |
| **IV — Certificação** | FIPS 140-3 e seus quatro níveis, PCI, Common Criteria, e o que "certificado" não significa |
| **V — O projeto hsm-a7** | Cada peça construída e o que ela corresponde num HSM real; resultados medidos; lições |
| **VI — O caminho adiante** | Fases 2 a 8 |
| **VII — Criptografia de pagamento** | PIN blocks ISO 9564, tradução de PIN, PVV e IBM 3624, decimalização, DUKPT — e o que deste domínio dá para ensinar aqui |
| **Apêndices** | Glossário, especificação do protocolo, pinagem, como reproduzir, **como operar o dispositivo**, leitura |

As Partes I a IV valem por si e não dependem deste projeto. Quem quer só
entender o assunto pode parar na IV; quem quer reproduzir o trabalho começa
na V. Quem tem a placa na mão e quer operá-la vai direto ao **apêndice E**.

### Dívida conhecida do manual

A Parte V (`manual/05-projeto.md`) é o capítulo-ponte: cada subseção pega um
arquivo e liga a peça de código ao conceito que ela implementa. **Ela só
cobre a Fase 1.**

O que as fases 2 e 3 construíram — o CFS, o TRNG e seus health tests, o
CTR_DRBG, o CMAC, o key store e a cerimônia de LMK — está descrito na
**Parte VI**, que se chama "O caminho adiante". Trabalho pronto documentado
no capítulo sobre o futuro: funciona como registro, mas inverte a promessa
feita na capa, e o leitor linear ganha a anatomia detalhada da parte menos
interessante e um resumo da mais interessante.

O conserto é escrever "Fase 2, peça por peça" e "Fase 3, peça por peça" no
mesmo molde da §24, reduzindo §27 e §28 a ponteiros. **Fica para a revisão
geral de documentação, depois que a Fase 3 fechar** — reescrever antes disso
significa reescrever de novo depois dos key blocks.

## Registro técnico

O diário de engenharia: números, decisões de implementação, atritos de
ferramenta. É o que se lê para **continuar o trabalho**, não para entender o
assunto.

- **[`fase1-notas.md`](fase1-notas.md)** — MMCM, configuração do NEORV32,
  síntese e timing, toolchain do firmware, bring-up em hardware.
- **[`fase2-notas.md`](fase2-notas.md)** — vetores KAT e sua procedência,
  cores de cripto, TRNG, CTR_DRBG, POST e CMAC.
- **[`fase3-notas.md`](fase3-notas.md)** — hierarquia de chaves: o que já
  existe, o que falta e **como retomar depois de desligar**.

## Criptografia de pagamento

A **Parte VII** do manual ([`manual/07-pagamento.md`](manual/07-pagamento.md))
cobre o domínio para o qual o projeto passou a apontar: PIN blocks ISO 9564
(formatos 0, 1, 3 e 4), tradução de PIN, verificação por PVV e IBM 3624, a
tabela de decimalização, e DUKPT nas variantes TDES e AES.

A seção 39 é a que mais importa para quem for mexer no código: ela separa o
que deste domínio é implementável aqui do que não é, e o critério **não é
dificuldade** — é a ausência de 3DES (decisão de arquitetura) e a
indisponibilidade de vetores de teste públicos.

## Referência

| Arquivo | Assunto |
|---|---|
| [`bancada.md`](bancada.md) | Gravação, diagnóstico de hardware e discriminadores de falha física. **Leia antes de depurar a placa** |
| [`pinout.md`](pinout.md) | Pinagem com procedência: verificado em hardware, no esquemático, ou ainda `[TBD]` |
| [`submodulos.md`](submodulos.md) | Política de código de terceiros e a escada de decisão para modificá-lo |
| [`../patches/`](../patches/) | Modificações em código de terceiros, com a justificativa junto do diff |
| [`puf-experimento.md`](puf-experimento.md) | Experimento de RO-PUF da Fase 6 — mede por que um PUF de FPGA é ruim |
| `utilization_fase3.txt`, `timing_fase3.txt` | Recursos e timing com o key store dentro |
| `utilization_fase1.txt` | Relatório de utilização (linha base de recursos) |
| `timing_fase1.txt` | Relatório de timing |
| `utilization_fase2.txt` | Utilização com o CFS (AES, SHA, DNA) |
| `timing_fase2.txt` | Timing com o CFS, incluindo a retimagem do SHA |
| `datasheets/` | Esquemáticos e manuais QMTECH |
| `qmtech_official_xdc/` | XDCs oficiais de exemplo — cuidado, alguns são do core board **sem** daughterboard |

## Fora de `doc/`

- [`../PLANO.md`](../PLANO.md) — plano das 8 fases, com entregáveis e
  critérios de aceitação. A seção 0 (restrições invioláveis) vem primeiro por
  um motivo.
- [`../CLAUDE.md`](../CLAUDE.md) — resumo operacional e regras de trabalho.
- [`../README.md`](../README.md) — instalação e comandos.

## Estado

**Fase 1 e fase 2 completas e validadas em hardware.** O POST roda a cada
boot e cobre AES-256, SHA-256, HMAC-SHA-256, CMAC-AES-256, CTR_DRBG, os
testes de partida do TRNG e o key store — todos contra vetores oficiais do
NIST e do IETF. Falha leva a `TAMPERED`. Da fase 2 falta apenas
`dieharder -a`, que não está instalado nesta máquina.

**Fase 3 em andamento.** CMAC, key store, a **cerimônia de LMK** e o
**display de estado** prontos — três componentes por XOR, KCV a cada passo,
dual control pelos dois botões físicos, a escada
`UNINITIALIZED → AUTHORIZED → OPERATIONAL`, e a placa soletrando o estado com
o ponto decimal confirmando a autorização. Faltam os key blocks X9.143, o
zeroize e o resto dos comandos `0x22`–`0x2F`. Ver
[`fase3-notas.md`](fase3-notas.md).

Nenhum `[TBD]` de pinagem. Cores dos LEDs, polaridade do display, ordem
física dos botões e **ordem dos dígitos do display** foram todos fechados
por medida em hardware.
