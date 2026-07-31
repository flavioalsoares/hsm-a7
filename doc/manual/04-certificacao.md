# Parte IV — Certificação

Um HSM comercial não é vendido pelo que faz, e sim pelo que **um terceiro
verificou** que ele faz. Esta parte explica o que os selos significam — e,
igualmente importante, o que não significam.

## 19. FIPS 140-3

A norma dos Estados Unidos para módulos criptográficos, hoje alinhada à
ISO/IEC 19790. Substituiu a FIPS 140-2, e a validação é feita pelo CMVP
(programa conjunto NIST/CCCS) por meio de laboratórios credenciados.

A norma define **quatro níveis**, e a diferença entre eles é quase toda
física.

### Nível 1

Requisitos mínimos. Algoritmos aprovados, implementados corretamente. **Sem
exigência de segurança física** — uma biblioteca de software rodando num PC
comum pode ser validada em nível 1.

Utilidade real: garante que o AES é AES de verdade e que os testes de
resposta conhecida existem. Não diz nada sobre proteger a chave de quem tem
acesso à máquina.

### Nível 2

Acrescenta **evidência de violação**: lacres, revestimentos ou invólucros que
mostrem que alguém abriu. E autenticação **por papel** — o módulo distingue
"operador" de "administrador".

A palavra-chave é *evidência*: o nível 2 não impede a violação, garante que
ela deixe marca.

### Nível 3

Aqui a coisa fica séria. Acrescenta:

- **Resistência e resposta à violação** — o módulo detecta a intrusão e
  **zeroiza** os parâmetros críticos de segurança;
- **autenticação por identidade** — não basta o papel, é preciso saber quem;
- **separação física ou lógica** das interfaces por onde entram e saem
  parâmetros críticos.

A maior parte dos HSMs comerciais de propósito geral é validada em nível 3.

### Nível 4

O topo. Um **envelope completo de proteção**: qualquer tentativa de acesso
físico, de qualquer direção, é detectada e responde com zeroização. E
acrescenta **proteção contra falhas ambientais** — o módulo detecta tensão ou
temperatura fora da faixa e zeroiza antes que a condição possa ser explorada.

O nível 4 é caro, e existem poucos produtos. É a resposta direta aos ataques
descritos na seção 17: se você pode congelar o chip ou baixar a tensão para
induzir falhas, o módulo precisa perceber e se destruir primeiro.

### O vocabulário que a norma impõe

Vale conhecer, porque aparece em toda documentação da área:

- **CSP** (*Critical Security Parameter*) — chave em claro, dado de
  autenticação, qualquer coisa cuja divulgação comprometa a segurança.
- **Estado de erro** — condição em que o módulo entra ao falhar um
  autoteste e na qual **não realiza operações criptográficas**.
- **Modo aprovado** — o conjunto de operações e algoritmos cobertos pela
  validação. Um módulo pode ter funções fora do modo aprovado; usá-las tira
  você da conformidade.
- **Autotestes** — os KAT da seção 11, exigidos na inicialização e sob
  condições específicas.

## 20. PCI: as regras de pagamentos

Enquanto FIPS avalia o **módulo**, o mundo de pagamentos regula também
**como ele é operado**.

**PCI PTS HSM** define requisitos de segurança para o equipamento usado em
processamento de PIN e chaves de pagamento.

**PCI PIN Security Requirements** cobre a operação: como chaves são geradas,
transportadas, carregadas, trocadas e destruídas. É daqui que vêm, como
exigência contratual e não como boa prática:

- **dual control** — nenhuma operação sensível de chave por uma pessoa só;
- **split knowledge** — nenhuma pessoa conhece uma chave inteira;
- **cerimônia documentada**, com testemunhas e registro;
- **key blocks** para transporte de chave — e há prazos de migração
  obrigatória para formatos como o TR-31.

É por isso que este projeto modela LMK, componentes e dual control com botões
físicos: no mundo de pagamentos esses mecanismos são **requisito auditado**,
não escolha de arquitetura.

## 21. Common Criteria

Norma internacional (ISO/IEC 15408) com abordagem diferente: em vez de níveis
fixos, define **perfis de proteção** — descrições do que um tipo de produto
deve fazer — e avalia produtos contra eles, com um nível de garantia
(**EAL 1 a 7**) que indica o rigor da avaliação, não a força da segurança.

Confusão comum, e vale desfazer: **EAL alto não significa "mais seguro"**.
Significa "avaliado com mais rigor e mais documentação formal". Um produto
simples avaliado em EAL 6 pode proteger menos que um produto rico em EAL 4 —
o que o EAL mede é a confiança na avaliação, não a altura do muro.

Na Europa, perfis como o EN 419221-5 cobrem módulos criptográficos para
serviços de confiança, e são o caminho para dispositivos de assinatura
qualificada sob o eIDAS.

## 22. O que "certificado" significa — e o que não significa

Esta seção é a mais importante da Parte IV.

### Significa

- Um laboratório independente verificou as afirmações do fabricante.
- Os algoritmos foram testados contra vetores oficiais.
- Existe documentação de fronteira, de estados, de papéis e de zeroização.
- Há um processo de reavaliação quando o produto muda.

### Não significa

**Não significa "inviolável".** Certificação estabelece um piso verificado,
não um teto. Módulos certificados já foram quebrados — e certificados são
revogados ou emendados quando isso acontece.

**Não significa que a sua configuração está segura.** A validação cobre o
módulo operando em **modo aprovado**, numa configuração específica descrita
na política de segurança. Usá-lo fora dali é usar um produto não validado
com um adesivo de validado.

**Não significa que o sistema em volta está seguro.** O HSM protege a chave.
Se a aplicação assina qualquer coisa que peçam, o atacante não precisa da
chave — ele pede a assinatura. Essa é, na prática, a falha mais comum em
implantações reais: um HSM impecável atrás de uma API de aplicação que
autoriza demais.

**Não significa nada sobre canal lateral, salvo se explicitado.** Resistência
a DPA é avaliada separadamente e nem sempre está incluída.

### A moral para este projeto

Não há nenhuma pretensão de certificação aqui, e nem poderia haver. Mas
conhecer a estrutura das normas explica **por que** as fases do plano estão
na ordem em que estão:

- os autotestes da Fase 2 são o requisito de autoteste do FIPS;
- a máquina de estados da Fase 3 é a separação de papéis;
- o zeroize com prova é o requisito de zeroização;
- o log de auditoria é a evidência;
- os sensores da Fase 6 são o nível 3/4 de resposta física.

Implementar cada mecanismo e depois ler o parágrafo da norma que o exige é
uma forma muito eficiente de entender a norma — e de perceber que ela não é
burocracia arbitrária, mas cicatriz acumulada.
