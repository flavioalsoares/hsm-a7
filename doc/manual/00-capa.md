---
title: "Construindo um HSM de brinquedo"
subtitle: "Como funciona um módulo criptográfico de hardware, aprendido de dentro para fora"
author: "Projeto hsm-a7 — Artix-7 XC7A35T"
lang: pt-BR
---

::: {.capa-nota}

**Sobre este documento**

Este é o material de um projeto didático: construir, do zero, um módulo
criptográfico com hierarquia de chaves, cerimônia de carga, key blocks e API
de host — reproduzindo a arquitetura de um HSM real em escala reduzida, num
FPGA Artix-7.

O documento tem duas metades que se encontram no meio. As Partes I a IV
explicam **como um HSM funciona e por quê**, independentemente deste projeto:
arquitetura, ameaças, ataques históricos e certificação. A Parte V explica
**o que foi construído** e liga cada peça de código ao conceito
correspondente. A Parte VI é o roteiro do que falta.

Quem quer só entender o assunto pode parar na Parte IV. Quem quer reproduzir
o trabalho começa na Parte V e volta às anteriores conforme a dúvida
aparecer.

:::

::: {.aviso}

**AVISO — este dispositivo não é um HSM**

Não há PUF, malha antitamper, sensores físicos, gerador de números
aleatórios certificado, nem qualquer validação FIPS, PCI ou Common Criteria.
As chaves ficam numa BRAM que qualquer um com o bitstream pode inspecionar
em simulação.

O objetivo é **entender a arquitetura de dentro para fora**, não proteger
material de chave real. Nenhuma chave de produção deve jamais ser carregada
neste dispositivo.

A honestidade sobre isso não é modéstia: saber exatamente **por que** este
aparelho não é seguro é metade do aprendizado. Cada ausência listada na
seção 22 corresponde a um mecanismo real que existe num HSM de verdade e
custa dinheiro, tempo de projeto e meses de avaliação.

:::
