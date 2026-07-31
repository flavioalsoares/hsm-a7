# Documentação — roteiro de leitura

Este é um projeto **didático**: o objetivo é entender como um HSM funciona
construindo um de brinquedo.

> **Este dispositivo não é um HSM.** Não há PUF, malha antitamper, sensores
> físicos, RNG certificado nem validação FIPS/PCI. Nenhuma chave de produção
> entra aqui. O valor está em entender a arquitetura de dentro para fora.

## O manual

**[`hsm-a7-manual.pdf`](hsm-a7-manual.pdf)** — 43 páginas, o documento
principal. Fonte em [`manual/`](manual/), legível como Markdown; o PDF é
gerado por `./scripts/mkpdf.sh`.

| Parte | Assunto |
|---|---|
| **I — O que é um HSM** | O problema que resolve, modelo de ameaça, as três propriedades, onde HSMs são usados |
| **II — Arquitetura interna** | Fronteira criptográfica, hierarquia de chaves, cerimônia de LMK, key blocks TR-31, máquina de estados, aleatoriedade, self-test, zeroização, log, ciclo de vida |
| **III — Como HSMs são atacados** | Ataques de API (tabela de decimalização, confusão de tipo, PIN blocks), canais laterais, injeção de falha, ataques físicos |
| **IV — Certificação** | FIPS 140-3 e seus quatro níveis, PCI, Common Criteria, e o que "certificado" não significa |
| **V — O projeto hsm-a7** | Cada peça construída e o que ela corresponde num HSM real; resultados medidos; lições |
| **VI — O caminho adiante** | Fases 2 a 7 |
| **Apêndices** | Glossário, especificação do protocolo, pinagem, como reproduzir, leitura |

As Partes I a IV valem por si e não dependem deste projeto. Quem quer só
entender o assunto pode parar na IV; quem quer reproduzir o trabalho começa
na V.

## Registro técnico

**[`fase1-notas.md`](fase1-notas.md)** — o diário de engenharia: números,
parâmetros do MMCM, configuração do NEORV32, resultados de síntese e timing,
atritos de toolchain, bring-up em hardware. É o que se lê para continuar o
trabalho, não para entender o assunto.

## Referência

| Arquivo | Assunto |
|---|---|
| [`pinout.md`](pinout.md) | Pinagem com procedência: verificado em hardware, no esquemático, ou ainda `[TBD]` |
| [`submodulos.md`](submodulos.md) | Política de código de terceiros e a escada de decisão para modificá-lo |
| [`puf-experimento.md`](puf-experimento.md) | Experimento de RO-PUF da Fase 6 — mede por que um PUF de FPGA é ruim |
| `utilization_fase1.txt` | Relatório de utilização (linha base de recursos) |
| `timing_fase1.txt` | Relatório de timing |
| `datasheets/` | Esquemáticos e manuais QMTECH |
| `qmtech_official_xdc/` | XDCs oficiais de exemplo — cuidado, alguns são do core board **sem** daughterboard |

## Fora de `doc/`

- [`../PLANO.md`](../PLANO.md) — plano das 7 fases, com entregáveis e
  critérios de aceitação. A seção 0 (restrições invioláveis) vem primeiro por
  um motivo.
- [`../CLAUDE.md`](../CLAUDE.md) — resumo operacional e regras de trabalho.
- [`../README.md`](../README.md) — instalação e comandos.

## Estado

Fase 1 completa e validada em hardware. Próxima é a Fase 2 (`PLANO.md` §3):
AES-256 e SHA-256 no fabric, TRNG, health tests SP 800-90B e POST com KAT —
a primeira criptografia do projeto.
