# Documentação — roteiro de leitura

Este é um projeto **didático**: o objetivo é entender como um HSM funciona
construindo um de brinquedo. A documentação foi organizada para ser lida
nessa ordem, não como referência solta.

> **Este dispositivo não é um HSM.** Não há PUF, malha antitamper, sensores
> físicos, RNG certificado nem validação FIPS/PCI. Nenhuma chave de produção
> entra aqui. O valor está em entender a arquitetura de dentro para fora.

## Por onde começar

**1. [`arquitetura.md`](arquitetura.md) — os conceitos, de cima para baixo**

O que um HSM resolve e por que ele é construído assim: fronteira
criptográfica, hierarquia de chaves, cerimônia de LMK, key blocks TR-31,
máquina de estados, geração de aleatoriedade, self-test, zeroização, log de
auditoria. Cada conceito com o *porquê*, não só a definição.

Leia isto primeiro se quiser entender o assunto.

**2. [`fase1-didatico.md`](fase1-didatico.md) — a ponte, de baixo para cima**

Pega cada arquivo que foi escrito e responde: *o que essa peça corresponde
num HSM real?* Um debounce de botão vira integridade de autorização; um
generic desligado vira endurecimento de plataforma; um teste de silêncio vira
higiene de canal lateral.

Cada peça termina com "o que ainda falta", porque a distância entre o
brinquedo e o real é o conteúdo do curso.

Leia isto para ligar código a conceito.

**3. [`fase1-notas.md`](fase1-notas.md) — o registro técnico**

Números, decisões de implementação, parâmetros do MMCM, configuração do
NEORV32, resultados de síntese e timing, atritos de toolchain, bring-up em
hardware. É o diário de engenharia.

Leia isto para reproduzir ou continuar o trabalho.

## Referência

| Arquivo | Assunto |
|---|---|
| [`pinout.md`](pinout.md) | Pinagem com procedência: o que foi verificado em hardware, no esquemático, ou ainda é `[TBD]` |
| [`submodulos.md`](submodulos.md) | Política de código de terceiros: por que não se edita `third_party/` e o que fazer quando parece necessário |
| [`puf-experimento.md`](puf-experimento.md) | Experimento de RO-PUF da Fase 6 — mede por que um PUF de FPGA é ruim |
| `utilization_fase1.txt` | Relatório de utilização (linha base de recursos) |
| `timing_fase1.txt` | Relatório de timing |
| `datasheets/` | Esquemáticos e manuais QMTECH |
| `qmtech_official_xdc/` | XDCs oficiais de exemplo — cuidado, alguns são do core board **sem** daughterboard |

## Fora de `doc/`

- [`../PLANO.md`](../PLANO.md) — o plano completo das 7 fases, com entregáveis
  e critérios de aceitação. A seção 0 (restrições invioláveis) vem primeiro
  por um motivo.
- [`../CLAUDE.md`](../CLAUDE.md) — resumo operacional e regras de trabalho.
- [`../README.md`](../README.md) — instalação e comandos.

## Estado

Fase 1 completa e validada em hardware. Próxima é a Fase 2 (`PLANO.md` §3):
AES-256 e SHA-256 no fabric, TRNG, health tests SP 800-90B e POST com KAT —
a primeira criptografia do projeto.
