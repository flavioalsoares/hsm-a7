# Parte VI — O caminho adiante

## 27. Fase 2 — engines e self-test *(em andamento)*

**Objetivo:** primitivas corretas e verificáveis. Correção antes de
desempenho.

| Bloco | Fonte | Estado |
|---|---|---|
| AES-256 | secworks/aes | **no CFS, verificado** |
| SHA-256 | secworks/sha256 | **no CFS, verificado** |
| `DNA_PORT` | primitiva Xilinx | **no CFS, verificado** |
| TRNG | neoTRNG (do NEORV32) | a fazer |
| CTR_DRBG | firmware | a fazer |

### O que já está feito

Os vetores KAT foram baixados das fontes oficiais — NIST CAVP para AES e
SHA, RFC 4231 para HMAC, SP 800-90A para o DRBG — com URL e hash SHA-256 de
cada arquivo registrados num manifesto. Nada foi escrito de memória.

Isso não é formalidade. A regra inviolável do projeto diz que, se um KAT
falha, o bug está no código e não no vetor — e essa regra só tem força se a
procedência do vetor for verificável por um terceiro. Um script rebaixa,
confere hash e reextrai; sobre um repositório limpo, o resultado é byte a
byte idêntico.

Os dois cores passam:

```
AES-256   405 vetores × 4 (ECB/CBC, cifra/decifra) = 1620
SHA-256   65 mensagens, 74 blocos
```

O AESAVS traz quatro tipos de vetor e todos foram usados, porque cada um
pega uma classe diferente de defeito: `VarKey` varre cada bit da chave
isoladamente e acha indexação errada na expansão; `VarTxt` varre cada bit do
bloco e acha ordem de byte e permutação trocadas. Um core que passa apenas
no `GFSbox` pode estar inteiro errado.

Uma divisão de responsabilidade ficou registrada e vai importar no firmware:
o core de AES faz ECB, e o encadeamento de CBC é de quem chama; o core de
SHA recebe blocos de 512 bits já preenchidos, e o *padding* também é de quem
chama. Testar o core com essas coisas embutidas misturaria falhas de
naturezas diferentes.

> **O teste encontrou um defeito no próprio teste.** O testbench de SHA
> reprovou com um sintoma característico: digests corretos, porém deslocados
> de um — a mensagem 1 devolvia o resultado da 0. Esperar apenas o sinal de
> "pronto" logo após o comando termina de imediato, porque o núcleo ainda
> não o baixou, e lê-se o resultado anterior. O testbench de AES passava com
> o mesmo handshake fraco, por sorte de temporização; recebeu a mesma
> correção. Teste que passa por sorte é dívida, não aprovação.

### O coprocessador: o CFS

Os cores entraram pelo **CFS** (*Custom Functions Subsystem*) do NEORV32 —
um slot de periférico projetado para receber coprocessadores. O arquivo do
upstream é um template feito para ser jogado fora; a substituição é feita
trocando qual arquivo o build compila, sem patch e sem tocar no submódulo.

É também por onde o `GET_DNA` finalmente se resolveu, fechando a última
sobra da Fase 1.

O CFS, e não um barramento externo, por um motivo de arquitetura: o
coprocessador precisa estar **dentro da fronteira criptográfica** (seção 5),
não pendurado num barramento que sai do die. Coerente com `XBUS_EN => false`,
que é a mesma decisão vista do outro lado.

Três escolhas do mapa de registradores merecem nota, porque cada uma é um
conceito da Parte II virando linha de RTL:

- **O único fio do CFS que chega ao toplevel está amarrado em zero.** Não
  existe caminho físico do bloco que guarda a chave até um pino. A fronteira
  deixa de ser promessa de firmware e vira topologia.
- **Chave e blocos de entrada são escrita-somente**; ler devolve zero. Não
  protege contra a CPU, que acabou de escrever a chave — evita criar um
  caminho de leitura que um bug use por acidente.
- **Não há AES-128.** O tamanho de chave é fixo no hardware. Um modo mais
  fraco alcançável por escrita em registrador seria um *downgrade* de graça,
  e a seção 15 mostra o que APIs fazem com modos mais fracos disponíveis.

E há um `WIPE` que não é decorativo: ele sobrescreve a **chave expandida**
dentro do core, não só o registrador visível. O teste correspondente é o que
separa zeroização de teatro de zeroização — depois do wipe, cifrar sem
carregar chave nenhuma tem de produzir o resultado sob a chave zero.

> **Um testbench a mais, para uma pergunta diferente.** Os KAT de core provam
> que o AES está certo. Não provam que o *caminho* entre a CPU e o AES está
> certo — um core correto atrás de um mapa de registradores com a ordem das
> palavras invertida produz resultados perfeitamente errados. Por isso os
> mesmos vetores do NIST são replicados uma segunda vez, agora **através do
> barramento**. Foi assim que a Fase 1 já tinha aprendido a separar
> "o módulo funciona" de "o sistema funciona".

### O preço em silício, e o que ele ensinou

Colocar criptografia no fabric custou caro e o custo apareceu onde não se
esperava.

| | Fase 1 | Com o CFS |
|---|---|---|
| Slice LUTs | 2240 (10,8%) | **7035 (33,8%)** |
| Flip-flops | 1633 (3,9%) | 6235 (15,0%) |
| Block RAM | 3,5 | 3,5 |
| DSP48E1 | 0 | 0 |

Área não foi problema — sobra um terço do chip. **Temporização foi.** O
projeto vinha com +0,637 ns de folga e, com os cores dentro, foi para
**−2,388 ns**: 58 caminhos falhando, o dispositivo não podia ser gravado.

O diagnóstico veio antes de qualquer conserto, e foi ele que economizou o
trabalho: dos 58 caminhos, **49 estavam no SHA-256 e 9 no AES**, e o pior do
AES era −0,087 ns — ruído. Um único bloco respondia por tudo. E dentro dele,
um único caminho: **oito somas de 32 bits encadeadas num ciclo só**, porque
a expansão da mensagem e a rodada de compressão dividem o mesmo ciclo.

A correção foi registrar as duas entradas combinacionais da rodada, com um
detalhe bonito: deslizar a janela da expansão uma rodada mais cedo faz os
quatro *taps* andarem junto, e a mesma fórmula que produzia `W[t]` passa a
produzir `W[t+1]`. Sem estágio de pipeline novo, sem ciclo a mais — ainda
são 64 rodadas por bloco.

```
+0,637 ns   Fase 1, sem criptografia
−2,388 ns   com o CFS                         não fecha
−1,215 ns   com esforço máximo de ferramenta  não fecha
+0,487 ns   com os dois patches de retimagem  fecha
```

> **A lição não é retimagem — é o que precisa existir antes de você poder
> tocar numa implementação criptográfica.**
>
> Modificar um core de hash é a espécie de coisa que se faz errado em
> silêncio: o resultado continua parecendo um hash. O que tornou isto
> aceitável foi a rede de vetores oficiais montada antes — 65 mensagens do
> SHAVS, rodadas no core e através do barramento. Foi possível **provar**
> que a modificação não mudou o resultado, sem tocar num vetor e sem
> relaxar um assert.
>
> É a mesma razão de o FIPS 140-3 exigir *self-test* (seção 11) e de o
> projeto ter a regra "se um KAT falha, o bug está no código". Sem isso,
> mexer ali seria irresponsável — e é exatamente por não ter essa rede que
> "não invente sua própria criptografia" é um bom conselho.

A modificação entrou como **patch versionado e revisável**, não como fork
nem reescrita: `third_party/` continua byte a byte igual ao upstream, e o
diff do que mudou está no repositório, legível, ao lado da justificativa.

### O que falta

Vêm agora o neoTRNG e o conteúdo real da fase: os **testes de saúde**
(seção 10) e o **POST** (seção 11). RCT e APT sobre a fonte bruta, e KAT de
AES, SHA, HMAC e DRBG antes de aceitar qualquer comando.

**Cuidado térmico registrado no plano:** manter o array de osciladores em
anel pequeno, meia dúzia de anéis. Centenas geram calor e ruído de
alimentação localizados sem ganho de entropia.

Critérios restantes: KAT passando também no POST; 1 MB de saída do gerador
passando em `ent` e `dieharder` (sanidade, não validação); e forçar falha
artificial no RCT levando o dispositivo a `TAMPERED`.

## 28. Fase 3 — hierarquia de chaves

O coração do projeto, e onde os conceitos das Partes II e III viram código.

- **Key store** com os campos do cabeçalho TR-31 modelados desde o início —
  refatorar isso depois é doloroso porque o MAC cobre o cabeçalho inteiro.
- **Máquina de estados** completa, com display de 7 segmentos mostrando
  `Uni` / `Aut` / `OPE` / `tPr`.
- **Cerimônia de LMK** com três componentes XOR, KCV a cada passo, e dual
  control exigindo os dois botões.
- **Key blocks TR-31 versão D**: KBEK e KBAK derivadas por CMAC, corpo em
  AES-CBC, autenticação por CMAC sobre cabeçalho e corpo.
- **Zeroize** com prova por dump.
- **Log de auditoria** gravado antes da execução, em flash, com contador
  monotônico.

O critério de aceitação que mais importa:

> Captura da UART durante toda a suíte não contém nenhum byte de chave em
> claro — `grep` automatizado contra as chaves conhecidas do teste.

É a fronteira criptográfica deixando de ser afirmação e virando medida
(seção 5).

Outros critérios: gerar chave, exportar em TR-31, reimportar e usar em AES
com resultado idêntico; parser Python e firmware C concordando em 100 blocos
aleatórios; alterar um bit do cabeçalho ou do corpo invalidando o MAC; e
chave marcada como não exportável não saindo **por caminho nenhum**.

## 29. Fase 4 — armazenamento não-volátil

Blobs embrulhados na flash SPI, MAC de integridade, contador anti-rollback,
recuperação de estado no boot.

O problema novo aqui é o **rollback**: um atacante que restaure um estado
antigo da flash pode reviver uma chave revogada ou desfazer um incremento de
contador. Por isso o contador monotônico precisa de proteção específica, e é
um dos pontos onde HSMs reais gastam esforço desproporcional.

Detalhe de arquitetura já mapeado: a flash é a **mesma** que guarda o
bitstream. Log e blobs precisam morar num offset acima da imagem de
configuração, e o acesso a partir da lógica do usuário exige a primitiva
`STARTUPE2` para dirigir o clock de configuração.

## 30. Fase 5 — API de host

Subconjunto de PKCS#11 (`C_Initialize`, `C_GenerateKey`, `C_WrapKey`,
`C_Sign`) como biblioteca compartilhada, ou um command set ASCII estilo
payShield.

É aqui que se entende por que a API é o que é: **é você que precisa impedi-la
de vazar material de chave**. Depois de ter lido a seção 15, escrever a API
com a pergunta "o que isto vaza em laço?" na cabeça é uma experiência
diferente.

## 31. Fase 6 — tamper e ataques

Duas metades.

**Defesa:** XADC monitorando temperatura e tensão, disparando zeroize fora de
faixa. É o mecanismo de proteção contra falhas ambientais do FIPS nível 4
(seção 19), em versão mínima.

**Ataque:** atacar o próprio HSM. Glitch de clock pela porta de
reconfiguração dinâmica do MMCM, observar a assinatura sair errada, e então
implementar contramedidas — dupla execução, verificação de resultado (seção
17.4).

Também: bitstream encriptado com chave em BBRAM, como confidencialidade de
firmware. E o experimento de RO-PUF, documentado à parte, que mede na própria
placa **por que** um PUF de FPGA é ruim e por que o corretor de erros é
obrigatório.

Esta é a fase mais divertida e a mais instrutiva: construir, quebrar,
reforçar.

## 32. Fase 7 — assimétrico

RSA-2048 por Montgomery nos 90 DSP48E1; P-256 depois.

Deixado por último de propósito: o aprendizado de arquitetura de HSM está nas
fases 3 a 5. E há um gancho direto com a seção 17.1 — implementar RSA-CRT
sem verificar a assinatura antes de emitir é reproduzir o ataque Bellcore no
próprio equipamento.

## 33. Ordem de trabalho, e a regra que a sustenta

Uma regra vale para todas as fases:

> **Nada vai para a placa sem passar antes no testbench.**

Depurar criptografia por UART, no hardware, sem visibilidade interna, é a
forma mais lenta possível de descobrir que faltou um byte no preenchimento.
Um erro de enquadramento em simulação custa segundos; o mesmo erro na bancada
custa uma tarde e várias hipóteses erradas.

A Fase 1 já demonstrou o retorno: dois defeitos reais foram pegos em
simulação, e o único que escapou até o hardware foi o único que a simulação
estruturalmente não podia ver.
