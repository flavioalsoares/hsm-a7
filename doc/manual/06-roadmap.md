# Parte VI — O caminho adiante

## 27. Fase 2 — engines e self-test *(em andamento)*

**Objetivo:** primitivas corretas e verificáveis. Correção antes de
desempenho.

| Bloco | Fonte | Estado |
|---|---|---|
| AES-256 | secworks/aes | **verificado em simulação** |
| SHA-256 | secworks/sha256 | **verificado em simulação** |
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

### O que falta

Os cores entram pelo **CFS** (*Custom Functions Subsystem*) do NEORV32 — um
slot de periférico projetado para receber coprocessadores. A substituição é
feita trocando qual arquivo o build compila, sem tocar no submódulo. É
também por onde o `GET_DNA` finalmente se resolve.

Depois vêm o neoTRNG e o conteúdo real da fase: os **testes de saúde**
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
