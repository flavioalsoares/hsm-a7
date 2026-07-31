# Experimento: RO-PUF no Artix-7 (fase 6)

Experimento educacional. **Não é raiz de confiança.** O objetivo é medir na
própria placa por que um PUF de FPGA é ruim e por que o fuzzy extractor é
obrigatório — não obter uma chave utilizável.

---

## 1. Princípio

Um oscilador em anel é uma cadeia de um número ímpar de inversores realimentada.
Ela oscila numa frequência que depende dos atrasos de porta e de roteamento —
ou seja, das variações de fabricação daquele die específico.

Dois ROs nominalmente idênticos oscilam em frequências ligeiramente diferentes.
Comparar os dois dá **1 bit**:

```
   bit = 1 se f[i] > f[j], senão 0
```

Com N pares, N bits. A "chave" é o vetor de comparações.

```
        enable ──┐
                 ▼
            ┌───────┐   ┌───┐   ┌───┐   ┌───┐
        ┌──►│  AND  ├──►│INV├──►│INV├──►│INV├──┬──► contador
        │   └───────┘   └───┘   └───┘   └───┘  │
        └──────────────────────────────────────┘
              (cadeia com numero impar de estagios)
```

---

## 2. Implementação no fabric — onde mora a dificuldade

Três detalhes que decidem se o experimento mede variação de silício ou apenas
mede o roteador da Vivado:

**Impedir a otimização.** A síntese adora colapsar uma cadeia de inversores em
nada. Cada inversor é um `LUT1` explícito com `DONT_TOUCH` / `KEEP_HIERARCHY`.
Sem isso o resultado é um circuito vazio ou um oscilador único replicado.

**Simetria de layout.** Cada RO precisa ocupar exatamente a mesma disposição
relativa de LUTs, com o mesmo roteamento. Isso exige `LOC` fixo por instância
ou um `pblock` por RO com a mesma geometria. Se os ROs tiverem layouts
diferentes, a diferença de frequência medida é dominada pela assimetria de
roteamento — que é *idêntica em todos os chips* e portanto não é um segredo.

Este é o ponto central e o motivo do experimento existir: num FPGA, a
componente determinística tende a superar a componente aleatória.

**Pareamento vizinho.** Comparar RO[i] com RO[i+1] fisicamente adjacentes
cancela gradientes sistemáticos (processo e temperatura variam suavemente ao
longo do die). Comparar cantos opostos mede o gradiente, não o PUF.

---

## 3. Regras de segurança do experimento

Alinhadas à restrição do projeto (`PLANO.md` §0): nada pode representar risco ao
hardware.

- **Habilitar apenas o par sob medição.** Todos os demais ROs desligados pelo
  AND de enable. Nunca 64 anéis oscilando juntos.
- Máximo de 64 ROs instanciados, cadeias curtas (5 a 9 estágios).
- **XADC monitorando temperatura durante todo o experimento.** Abortar acima de
  70 °C. O aquecimento é o próprio objeto de estudo, não um efeito colateral a
  ignorar.
- Janela de contagem curta (1 ms basta) — não deixar oscilando à toa.
- Nada de fonte externa de calor ou frio. A variação térmica vem do
  autoaquecimento controlado do die (seção 5).

---

## 4. Medida 1 — confiabilidade (intra-chip)

O que se pode medir com **uma única placa**.

Procedimento: ler o vetor de N bits 100 vezes, em condições estáveis. Comparar
cada leitura com uma referência (maioria bit a bit).

```
  BER = média( HD(resposta_k, referência) ) / N
```

Um PUF de silício decente fica abaixo de 1e-6 após correção; a resposta bruta
fica na casa de 1 a 10 %. **Espere valores ruins aqui** — é o resultado
esperado e é o conteúdo do experimento.

Registrar também os **bits instáveis**: aqueles cujos dois ROs têm frequências
quase iguais. Eles trocam de valor a cada leitura e são a origem do ruído.
Contar quantos por cento do vetor são efetivamente inúteis.

## 5. Medida 2 — deriva térmica

Habilitar um bloco de lógica de carga (shift registers com toggle alto) para
aquecer o die, lendo a temperatura pelo XADC. Amostrar o PUF a cada 5 °C de
subida, dentro do limite de 70 °C.

Plotar BER × temperatura. A curva sobe. Esse gráfico é a resposta visual para
"por que não posso usar a saída do PUF direto como chave".

## 6. Medida 3 — uniformidade e viés

```
  uniformidade = (número de bits 1) / N     → ideal 50 %
```

Desvio grande indica que a assimetria de roteamento está dominando. Vale repetir
com um pareamento diferente e observar a mudança — evidência direta do problema
descrito na seção 2.

**Não é possível medir unicidade (inter-chip)** com uma placa só. O proxy
imperfeito é comparar regiões distintas do mesmo die tratando-as como "chips"
diferentes; anotar explicitamente que é proxy, não medida.

---

## 7. Fuzzy extractor — a parte que realmente ensina

Com o BER medido, dimensionar o corretor:

1. **Enrollment:** ler resposta `w`, gerar chave aleatória `k`, calcular
   `helper = w XOR BCH_encode(k)`. O helper data é **público** — guardar na SPI
   flash sem proteção, deliberadamente.
2. **Reconstrução:** ler `w'` (ruidosa), calcular
   `BCH_decode(w' XOR helper)` → recupera `k` exatamente, se o número de erros
   estiver dentro da capacidade do código.

Dimensionamento: com BER de 5 % e 255 bits, espera-se ~13 erros. Um BCH(255,
k, t) precisa de t ≥ 13 com margem — o que consome uma fatia grande dos bits.

**A conta que vale a pena fazer:** quantos bits de entropia sobram depois de
publicar o helper data? Cada bit de paridade exposto é entropia perdida do
segredo. Descobrir que 255 bits de PUF ruidoso rendem talvez 60 a 80 bits de
chave utilizável é o momento em que o conceito para de ser abstrato.

---

## 8. Entregável

Tabela em `doc/puf_resultados.md`:

| Métrica | Valor medido | Referência (PUF de silício) |
|---|---|---|
| BER bruto (25 °C) | | 1–10 % |
| BER bruto (60 °C) | | — |
| Bits instáveis | | < 5 % |
| Uniformidade | | ~50 % |
| Entropia após helper data | | — |

E a conclusão honesta: comparar o que se obteve com o que um Zynq UltraScale+ ou
PolarFire entrega, e explicar a diferença em termos de layout controlado no
silício versus roteamento de FPGA.

---

## 9. Leitura

- Suh & Devadas (2007) — o paper que estabeleceu o RO-PUF
- Maes, *Physically Unclonable Functions* (Springer) — fuzzy extractors a fundo
- Herder et al. (2014) — survey, bom para o panorama de ataques a PUF
