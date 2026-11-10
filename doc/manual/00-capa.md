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
arquitetura, ameaças, ataques históricos e certificação. A Parte V descreve
**a plataforma do equipamento** e liga cada peça ao conceito correspondente.
A Parte VI descreve **as funções que cada fase acrescentou**: primitivas e
autoteste, hierarquia de chaves, armazenamento e log, API de host, resposta
a violação e criptografia assimétrica. A Parte VII trata do domínio para o
qual o projeto aponta: **criptografia de pagamento** — PIN blocks, tradução
de PIN, verificação por PVV e 3624, DUKPT — e diz, sem rodeio, o que deste
domínio é ensinável aqui e o que não é.

O equipamento tem AES-256, SHA-256, HMAC, CMAC, TRNG com health tests da
SP 800-90B, CTR_DRBG e RSA-2048, todos conferidos contra vetores no
autoteste de cada boot. Tem também key store, cerimônia de LMK com dual
control, key blocks X9.143, zeroização com prova, armazenamento persistente,
log de auditoria, porta host ASCII e resposta a violação. O histórico da
construção e as medidas ficam nas notas de fase, fora deste manual.

Quem quer só entender o assunto pode parar na Parte IV — ou seguir para a
VII, se o interesse for pagamento. Quem quer reproduzir o trabalho começa na
Parte V e volta às anteriores conforme a dúvida aparecer. Quem tem a placa
na mão e quer operá-la vá direto ao **apêndice E**, que percorre uma sessão
inteira: ligar, autoteste, cerimônia, ativação e o trabalho com chaves.

:::

::: {.aviso}

**AVISO — este dispositivo não é um HSM**

Não há PUF, malha antitamper, invólucro com detecção de violação, gerador
de números aleatórios certificado, nem qualquer validação FIPS, PCI ou Common Criteria.
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

---

**Licença.** Este manual e o código do projeto estão sob a **Apache License
2.0**. O texto integral está em `LICENSE`, no repositório.

**Independência.** Este documento não nomeia fabricante nem produto de HSM,
e não há vínculo, patrocínio, endosso ou alegação de compatibilidade com
equipamento comercial algum. O conteúdo vem de normas públicas — ISO, ANSI,
NIST, IETF — e de literatura acadêmica publicada; nada é derivado de
documentação proprietária. Ver `THIRD-PARTY.md`.
