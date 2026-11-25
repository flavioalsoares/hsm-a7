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


<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<rect class="cxd" x="20" y="10" width="640" height="230" rx="6"/>
<text x="35" y="30" class="tb td">Nível 4</text><text x="100" y="30" class="ts">envelope completo; falha ambiental (tensão, temperatura) zeroiza</text>
<rect class="cxd" x="45" y="42" width="590" height="188" rx="6" style="fill:#f9eeec"/>
<text x="60" y="62" class="tb td">Nível 3</text><text x="125" y="62" class="ts">detecta a intrusão e zeroiza; autenticação por identidade; interfaces separadas</text>
<rect class="cx" x="70" y="74" width="540" height="146" rx="6"/>
<text x="85" y="94" class="tb">Nível 2</text><text x="150" y="94" class="ts">evidência de violação (lacre, revestimento); autenticação por papel</text>
<rect class="cxv" x="95" y="106" width="490" height="104" rx="6"/>
<text x="110" y="126" class="tb">Nível 1</text><text x="175" y="126" class="ts">algoritmos aprovados e corretos; autotestes; sem exigência física</text>
<text x="340" y="160" text-anchor="middle" class="ts">uma biblioteca de software num PC comum pode chegar aqui</text>
<text x="340" y="190" text-anchor="middle" class="ts">a maior parte dos HSM de propósito geral está no nível 3</text>
</svg>
<figcaption>Figura 19.1 — Os níveis da FIPS 140-3. Cada nível contém o anterior; a diferença é quase toda física.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="20" y="30" width="240" height="150" rx="8"/>
<text x="140" y="52" text-anchor="middle" class="tb">FIPS 140-3</text>
<text x="140" y="70" text-anchor="middle" class="ts">o módulo</text>
<text x="40" y="100" class="ts">algoritmos, autotestes</text>
<text x="40" y="116" class="ts">fronteira, papéis, estados</text>
<text x="40" y="132" class="ts">zeroização, segurança física</text>
<rect class="cx" x="220" y="20" width="230" height="170" rx="8" style="fill:#f1f1ee;opacity:0.9"/>
<text x="335" y="42" text-anchor="middle" class="tb">PCI PTS HSM</text>
<text x="335" y="60" text-anchor="middle" class="ts">o equipamento de pagamento</text>
<text x="240" y="92" class="ts">resistência física</text>
<text x="240" y="108" class="ts">funções de PIN seguras</text>
<text x="240" y="124" class="ts">proteção da LMK</text>
<rect class="cxd" x="410" y="30" width="250" height="150" rx="8" style="opacity:0.95"/>
<text x="535" y="52" text-anchor="middle" class="tb">PCI PIN Security</text>
<text x="535" y="70" text-anchor="middle" class="ts">como ele é operado</text>
<text x="465" y="100" class="ts">dual control, split knowledge</text>
<text x="465" y="116" class="ts">cerimônia com testemunhas</text>
<text x="465" y="132" class="ts">key blocks no transporte</text>
<text x="465" y="148" class="ts">prazos de migração</text>
</svg>
<figcaption>Figura 20.1 — Três normas, três objetos. A FIPS avalia o módulo; o PCI avalia também o equipamento de pagamento e a forma de operá-lo.</figcaption>
</figure>

## 21. Common Criteria

Norma internacional (ISO/IEC 15408) com abordagem diferente: em vez de níveis
fixos, define **perfis de proteção** — descrições do que um tipo de produto
deve fazer — e avalia produtos contra eles, com um nível de garantia
(**EAL 1 a 7**) que indica o rigor da avaliação, não a força da segurança.

Confusão comum, e vale desfazer: **EAL alto não significa "mais seguro"**.
Significa "avaliado com mais rigor e mais documentação formal". Um produto
simples avaliado em EAL 6 pode proteger menos que um produto rico em EAL 4 —
o que o EAL mede é a confiança na avaliação, não a altura do muro.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="70" y1="190" x2="640" y2="190" marker-end="url(#seta)"/>
<line class="ln" x1="70" y1="190" x2="70" y2="15" marker-end="url(#seta)"/>
<text x="355" y="220" text-anchor="middle" class="ts">o que o produto protege (a altura do muro)</text>
<text x="30" y="105" class="ts" transform="rotate(-90 30 105)" text-anchor="middle">rigor da avaliação (EAL)</text>
<g class="ts"><text x="62" y="174" text-anchor="end">EAL 2</text><text x="62" y="134" text-anchor="end">EAL 4</text><text x="62" y="94" text-anchor="end">EAL 6</text></g>
<line class="grade" x1="70" y1="170" x2="630" y2="170"/><line class="grade" x1="70" y1="130" x2="630" y2="130"/><line class="grade" x1="70" y1="90" x2="630" y2="90"/>
<circle cx="200" cy="90" r="9" fill="#2d4f73"/><text x="214" y="86" class="ts">produto A: simples,</text><text x="214" y="99" class="ts">avaliado com muito rigor</text>
<circle cx="500" cy="130" r="9" fill="#7a1f1f"/><text x="514" y="126" class="ts">produto B: rico,</text><text x="514" y="139" class="ts">avaliado com rigor médio</text>
</svg>
<figcaption>Figura 21.1 — O EAL mede a confiança na avaliação. Um produto com EAL maior pode proteger menos que outro com EAL menor.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cxd" x="20" y="20" width="640" height="40"/>
<text x="340" y="38" text-anchor="middle" class="tb">aplicação</text>
<text x="340" y="52" text-anchor="middle" class="ts td">não coberta: se ela assina tudo o que pedem, o atacante só pede</text>
<rect class="cxd" x="60" y="70" width="560" height="40"/>
<text x="340" y="88" text-anchor="middle" class="tb">configuração e operação</text>
<text x="340" y="102" text-anchor="middle" class="ts td">não coberta: fora do modo aprovado, o selo não vale</text>
<rect class="cxv" x="100" y="120" width="480" height="40"/>
<text x="340" y="138" text-anchor="middle" class="tb">o módulo, em modo aprovado</text>
<text x="340" y="152" text-anchor="middle" class="ts">coberto: o que o laboratório verificou</text>
<rect class="cxc" x="140" y="170" width="400" height="26"/>
<text x="340" y="188" text-anchor="middle" class="ts">canal lateral: só se a avaliação o incluir</text>
</svg>
<figcaption>Figura 22.1 — O que um certificado cobre numa implantação. A falha mais comum está na camada de cima, que nenhum selo cobre.</figcaption>
</figure>

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
