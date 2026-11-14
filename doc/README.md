# Documentação — roteiro de leitura

Este é um projeto **didático**: o objetivo é entender como um HSM funciona
construindo um de brinquedo.

> **Este dispositivo não é um HSM.** Não há PUF, malha antitamper, invólucro
> com detecção de violação, RNG certificado nem validação FIPS/PCI. Nenhuma chave de produção
> entra aqui. O valor está em entender a arquitetura de dentro para fora.

## O manual

**[`hsm-a7-manual.pdf`](hsm-a7-manual.pdf)** — 88 páginas, o documento
principal. Fonte em [`manual/`](manual/), legível como Markdown; o PDF é
gerado por `./scripts/mkpdf.sh`.

| Parte | Assunto |
|---|---|
| **I — O que é um HSM** | O problema que resolve, modelo de ameaça, as três propriedades, onde HSMs são usados |
| **II — Arquitetura interna** | Fronteira criptográfica, hierarquia de chaves, cerimônia de LMK, key blocks TR-31, máquina de estados, aleatoriedade, self-test, zeroização, log, ciclo de vida |
| **III — Como HSMs são atacados** | Ataques de API (tabela de decimalização, confusão de tipo, PIN blocks), canais laterais, injeção de falha, ataques físicos |
| **IV — Certificação** | FIPS 140-3 e seus quatro níveis, PCI, Common Criteria, e o que "certificado" não significa |
| **V — O equipamento hsm-a7** | Objetivo, plataforma, restrições, e cada peça da plataforma ligada ao que ela é num HSM real |
| **VI — As funções, fase a fase** | O que cada fase acrescentou, e o conceito por trás: fases 2 a 8 |
| **VII — Criptografia de pagamento** | PIN blocks ISO 9564, tradução de PIN, PVV e IBM 3624, decimalização, DUKPT — e o que deste domínio dá para ensinar aqui |
| **Apêndices** | Glossário, especificação do protocolo, pinagem, como reproduzir, **como operar o dispositivo**, leitura |

As Partes I a IV valem por si e não dependem deste projeto. Quem quer só
entender o assunto pode parar na IV; quem quer reproduzir o trabalho começa
na V. Quem tem a placa na mão e quer operá-la vai direto ao **apêndice E**.

O manual tem só conceitos e uso. O histórico da construção, as medidas e os
testes ficam nas notas de fase, abaixo.

## Registro técnico

O registro de engenharia de cada fase: números, decisões de implementação,
testes e atritos de ferramenta. É o que se lê para **continuar o trabalho**,
não para entender o assunto.

| Arquivo | Assunto |
|---|---|
| [`fase1-notas.md`](fase1-notas.md) | MMCM, configuração do NEORV32, síntese e timing, toolchain, bring-up em hardware |
| [`fase2-notas.md`](fase2-notas.md) | Vetores KAT e procedência, cores de cripto, CFS, TRNG, CTR_DRBG, POST e CMAC |
| [`fase3-notas.md`](fase3-notas.md) | Hierarquia de chaves: key store, cerimônia, key block, zeroize, comandos de chave |
| [`fase4-notas.md`](fase4-notas.md) | Flash como memória segura, registro persistente, log de auditoria |
| [`fase5-notas.md`](fase5-notas.md) | Porta host ASCII, troca de chaves sob KEK, checagem de uso |
| [`fase6-notas.md`](fase6-notas.md) | Sensores, perda de lock, resposta a violação, glitch, dupla execução, BBRAM |
| [`fase7-notas.md`](fase7-notas.md) | RSA-2048: Montgomery no CFS, CRT, geração de chave, comandos `R0`/`R2`/`R4` |

## Criptografia de pagamento

A **Parte VII** do manual ([`manual/07-pagamento.md`](manual/07-pagamento.md))
cobre o domínio para o qual o projeto passou a apontar: PIN blocks ISO 9564
(formatos 0, 1, 3 e 4), tradução de PIN, verificação por PVV e IBM 3624, a
tabela de decimalização, e DUKPT nas variantes TDES e AES.

A seção 37 é a que mais importa para quem for mexer no código: ela separa o
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
| [`puf_resultados.md`](puf_resultados.md) | O que o RO-PUF mediu nesta placa |
| `utilization_fase7.txt`, `timing_fase7.txt` | Recursos e timing com o RSA dentro do SoC |
| `utilization_fase6.txt`, `timing_fase6.txt` | Recursos e timing com o XADC e a perda de lock |
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

O estado de cada fase está no início da nota da fase e em `../CLAUDE.md`.
