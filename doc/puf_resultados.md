# RO-PUF: resultados

Medido em 2026-11-06, numa placa, com `build/puf/hsm_puf.bit` e `host/puf.py`.
Método em `doc/puf-experimento.md`. **Não é raiz de confiança**, e nada neste
bitstream toca o HSM.

## Resumo

| Métrica | Medido | Referência do plano |
|---|---|---|
| BER bruto, 40 °C | 2,3% e 3,8% (dois bitstreams) | 1–10% |
| BER bruto, 48 °C | 3,1% (faixa 1,75–5,2%) | — |
| BER bruto, 60 °C | **não alcançado** | — |
| Bits instáveis | 6,2% e 12,5% | < 5% |
| Uniformidade | 43,8% e 59,4% | ~50% |
| Chave depois do helper | 47 a 79 bits, em 255 | 60 a 80 |

Os números são do pareamento de vizinhos, 32 bits independentes.

## Montagem

64 anéis de sete estágios, um por CLB, em quatro colunas `CLBLL_L` de 16 linhas,
todas na mesma região de clock. Cada anel oscila sozinho, em janela de 1 ms, e um
só contador conta. Os pares são formados em `puf.py`, sobre a mesma medida, e por
isso trocar de pareamento não pede outro bitstream.

**A simetria precisa ser forçada.** Com `LOC` fixo e o roteador livre, os 64 anéis
saíram com 54 rotas diferentes. Com os pinos dos LUTs travados, a saída fora do
laço por um LUT tampão e a rota do anel 0 copiada para os demais com `FIXED_ROUTE`,
saíram **com uma rota só**. `build/puf/rotas.txt` é a prova de cada build.

Desvios do plano:

- Um anel ligado por vez, e não o par. É mais estrito, e evita acoplamento entre os
  dois.
- 64 anéis dão 32 bits independentes. Os 255 bits da seção 7 são extrapolação do BER
  medido; precisariam de 510 anéis, acima do limite do plano.
- A carga de 20 480 flip-flops ganhou um corte de hardware em `VCCINT` abaixo de
  0,95 V, além do corte de 70 °C.

## Frequência

| Coluna | Média | Desvio |
|---|---|---|
| 0 | 268,9 MHz | 1,20 |
| 1 | 271,6 MHz | 1,35 |
| 2 | 272,9 MHz | 1,63 |
| 3 | 262,8 MHz | 1,10 |

Ruído por anel, entre leituras: 0,02%. A variação dentro de uma coluna é de 0,5%.

**Entre colunas o die manda.** A coluna 3 fica 10 MHz abaixo da coluna 2, mesmo com
rotas idênticas, e os 16 bits dessa fronteira saem iguais. Esse pareamento dá BER
zero e parece ótimo. Mas o que ele mede é a posição no die, que seria a mesma em
todos os chips: é um bit estável sem segredo nenhum. Por isso se pareiam vizinhos.

## Confiabilidade

1000 varreduras por bitstream, a 40 °C, contra a maioria bit a bit.

| Pareamento | Bits | BER | Instáveis | Uniformidade |
|---|---|---|---|---|
| Vizinhos | 32 | 3,75% | 4 | 59,4% |
| Cadeia | 60 | 2,80% | 7 | 50,0% |
| Colunas | 48 | 0,00% | 0 | 45,8% |

O erro não se espalha: quase todo ele vem de poucos pares com frequências quase
iguais. A tabela é do segundo bitstream; o primeiro deu 2,31% e 2 instáveis nos
vizinhos.

## Deriva térmica

Nove níveis de carga, de 0 a 8, 200 varreduras em cada um, contra a referência fria.

| Carga | Temperatura | Frequência média | `VCCINT` | BER vizinhos |
|---|---|---|---|---|
| 0 | 40,0 °C | 268,98 MHz | 0,986 V | 2,80% |
| 2 | 42,5 °C | 266,58 MHz | 0,984 V | 4,72% |
| 4 | 44,6 °C | 264,89 MHz | 0,981 V | 3,44% |
| 6 | 45,8 °C | 263,47 MHz | 0,979 V | 3,33% |
| 8 | 48,1 °C | 262,01 MHz | 0,978 V | 3,09% |

**A curva prevista não apareceu.** O plano esperava o BER subindo com a temperatura.
Ele oscilou de 1,75% a 5,2%, sem tendência. Motivos que a medida permite dizer:

- Todos os anéis caem juntos, 2,6% em 8 °C. Comparar dois anéis cancela o que é
  comum.
- A faixa foi curta. A carga máxima parou em 48 °C, e não há como dizer o que
  aconteceria a 60 °C.
- Temperatura e `VCCINT` mudaram juntas, e esta medida não as separa.

## Unicidade

Uma placa não mede unicidade. O proxy é tratar cada coluna como um chip: 48,9% de
distância média, com ideal de 50%, mas de 20% a 60% entre pares de colunas, e com
só 15 bits por coluna. Não é medida entre chips.

## A resposta depende do bitstream

Mesmo chip, mesmos anéis no mesmo lugar, mesma rota. Só a lógica em volta mudou,
de 5120 para 20 480 flip-flops de carga, desligados nas duas medidas.

| Comparação | Vizinhos | Cadeia |
|---|---|---|
| Bitstream A contra B | 7 de 32 (21,9%) | 11 de 60 (18,3%) |
| Mesma configuração, minutos depois | 1 de 32 (3,1%) | 1 de 60 (1,7%) |
| Mesmo bitstream, recarregado | 2 de 32 (6,2%) | 2 de 60 (3,3%) |
| Entre duas recargas seguidas | 0 de 32 | 0 de 60 |

A diferença vem do bitstream, e não do ato de reconfigurar. Os bits que mudam na
recarga já eram instáveis: valiam 1 em 58% a 66% das varreduras antes de recarregar.
Entre A e B, 6 dos 7 bits viraram por inteiro, de 0% para 100% das varreduras ou o
inverso, e só o sétimo era instável. As recargas foram medidas a 38 °C, e as outras
linhas a 40 °C.

Consequência: a resposta deste PUF é uma propriedade do par chip e bitstream. Mudar
o projeto em volta dos anéis troca parte da chave derivada, mesmo com os anéis
travados no lugar.

## Corretor de erros

`puf.py corretor`, BCH de 255 bits, falha de reconstrução abaixo de 10⁻⁶. O `k` vem
das classes ciclotômicas, calculado.

| BER | Erros em 255 | Código | Paridade publicada | Chave |
|---|---|---|---|---|
| 3,75% | 9,6 | BCH(255, 79, 27) | 176 bits | 72 a 79 bits |
| 5,22% | 13,3 | BCH(255, 47, 33) | 208 bits | 47 bits |

A conta confirma o ponto da seção 7: de 255 bits ruidosos sobra menos de um terço.
Ela ainda é otimista, porque trata os bits como independentes e só desconta o viés
de primeira ordem. Os pares da mesma coluna não têm essa independência garantida.

## Conclusão

Três coisas impedem usar esta saída como chave:

1. A resposta bruta erra, e o corretor consome dois terços dos bits.
2. Parte da diferença entre anéis é geometria do die, igual em todos os chips.
3. A resposta muda com a lógica em volta, então o segredo ficaria amarrado a um
   bitstream.

Um PUF dedicado no silício tem layout controlado pelo fabricante do chip, em vez de
um roteador de FPGA travado à mão. Este experimento não mede um, então a comparação
fica nesse nível.
