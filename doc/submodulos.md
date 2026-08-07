# Cores externos e submódulos

Como este projeto lida com código de terceiros. A regra curta está no
`CLAUDE.md`; aqui estão o raciocínio e as receitas.

## Estado atual

| Submódulo | Versão | Commit | Modificações nossas |
|---|---|---|---|
| `third_party/neorv32` | v1.13.3 | `b217ead5` | **nenhuma** |
| `third_party/aes` | — | `80dc4718` | **nenhuma** |
| `third_party/sha256` | — | `837c5cc3` | **nenhuma** |

Os dois cores de cripto (secworks) estão fixados por **SHA de commit**, não
por tag: o `aes` não publica tags, e a única do `sha256` é de 2023. SHA de
commit é igualmente imutável — o que se queria evitar era seguir um *branch*,
que se move.

## Por que não se edita `third_party/` direto

Um submódulo é **outro repositório**. O nosso registra apenas um SHA. Editar
um arquivo lá dentro produz uma mudança que:

- não fica guardada em lugar nenhum do nosso repositório — só no disco;
- é **descartada em silêncio** por `git submodule update`, que qualquer
  checkout `--recurse-submodules` e qualquer CI executam;
- não existe num clone novo, que traz o commit fixado.

Funciona na sua máquina e some para todo mundo.

Num dispositivo criptográfico há um agravante: o SHA fixado **é** a afirmação
de procedência — "foi este código que sintetizei". Uma edição local quebra
essa afirmação sem deixar rastro: o pin continua dizendo `v1.13.3` enquanto o
bitstream contém outra coisa.

`scripts/mirror-deps.sh` **recusa** rodar com submódulo sujo, por esse motivo.

## Escada de decisão

Quando parecer necessário mudar um core externo, descer a lista na ordem:

### 0. Confirme que é mudança, e não configuração

Quase sempre é configuração. No NEORV32 foi 100% disso:
`rtl/soc/neorv32_wrapper.vhd` ajusta ~130 generics sem tocar num byte do core.

### 1. Existe ponto de extensão projetado?

Então não é modificação. É o caso da Fase 2 — ver a receita do CFS abaixo.

### 2. Patch em `patches/`, aplicado pelo build

Para correção pequena de bug ou incompatibilidade de ferramenta no upstream.
Preserva rastreabilidade e sobrevive a clone limpo. Custo: apodrece quando o
upstream mexe na região, e a aplicação precisa ser idempotente.

Convenção herdada do projeto irmão `msxinart`, que já usa
`patches/0001-*.patch`.

### 3. Fork + repontar o submódulo

```bash
git submodule set-url third_party/neorv32 git@github.com:voce/neorv32.git
git submodule sync --recursive
```

**Gatilho — não forkar "por precaução".** Só quando:

- houver **pelo menos um patch que precise persistir** e o `patches/` já
  estiver desconfortável (dois ou três arquivos, ou um patch que conflita a
  cada atualização); **ou**
- for preciso rebasear mudanças nossas sobre releases novas com regularidade.

Motivo de não antecipar: um fork cria obrigação permanente de rebase, e forks
apodrecem. Ficar preso na v1.13.3 enquanto o upstream corrige bugs de CPU é
pior, para um dispositivo criptográfico, do que o risco que o fork cobria.

E fork no GitHub troca dependência do *stnolting* por dependência do
*GitHub* — resolve menos "independência de terceiros" do que parece. Quem
resolve isso é o espelho (abaixo).

### 4. Vendorizar o arquivo, ou o core inteiro

Último recurso, quando na prática assumimos a manutenção.

## Mecânica: dois commits, um em cada repositório

Se houver fork, o erro clássico é esquecer o segundo:

```bash
cd third_party/neorv32
git checkout -b hsm-a7/fix-xyz
git commit -am "..."
git push fork hsm-a7/fix-xyz

cd ../..
git add third_party/neorv32      # <-- grava o SHA NOVO no repo pai
git commit -m "neorv32: bump para o fork com fix-xyz"
```

Sem o `git add` no pai, o fork tem a mudança mas o projeto continua apontando
para o SHA antigo, e ninguém enxerga. Aconteceu em escala menor na Fase 1: o
`git submodule add` gravou o HEAD do clone (`main`) e foi preciso re-adicionar
depois do checkout da tag.

Para deriva não passar despercebida:

```bash
git config status.submoduleSummary true
git config diff.submodule log
git submodule foreach --recursive 'git status --short'
```

## Receita: substituir o CFS — **feito na Fase 2**

`neorv32_cfs.vhd` é o Custom Functions Subsystem — um **template feito para
ser substituído**. É onde AES-256, SHA-256 e o `DNA_PORT` entram como
coprocessadores.

Não editar o arquivo no submódulo. O binding em VHDL é por nome de entidade
dentro da biblioteca, então basta trocar qual arquivo é compilado. Em
`scripts/build.tcl`, depois de montar `$neorv32_files`:

```tcl
# tira o CFS do upstream da lista e usa o nosso no lugar
set cfs_upstream $neorv32/rtl/core/neorv32_cfs.vhd
if {[lsearch -exact $neorv32_files $cfs_upstream] < 0} {
    error "neorv32_cfs.vhd nao esta na lista do upstream"
}
set neorv32_files [lsearch -all -inline -not $neorv32_files $cfs_upstream]
add_files rtl/crypto/neorv32_cfs.vhd
set_property library neorv32 [get_files rtl/crypto/neorv32_cfs.vhd]
```

A verificação antes do filtro não é paranoia barata: `lsearch -not` sobre um
arquivo que não está na lista **não reclama**, só não remove nada. Se o
upstream renomear o CFS, sem essa checagem o build compilaria os dois e o
erro apareceria como duplicata de entidade — longe da causa.

O mesmo em `scripts/sim.sh`, filtrando a linha antes do `xvhdl -work neorv32`.

Resultado: submódulo intocado, zero patch, e o código de cripto visível nos
nossos diffs — que é exatamente onde ele tem de estar num projeto de
segurança.

A entidade a respeitar é (`rtl/core/neorv32_cfs.vhd`):

```vhdl
entity neorv32_cfs is
  port (
    clk_i     : in  std_ulogic;
    rstn_i    : in  std_ulogic;
    bus_req_i : in  bus_req_t;
    bus_rsp_o : out bus_rsp_t;
    irq_o     : out std_ulogic;
    cfs_in_i  : in  std_ulogic_vector(255 downto 0);
    cfs_out_o : out std_ulogic_vector(255 downto 0)
  );
```

Lembrar de ligar `IO_CFS_EN => true` no wrapper.

### A armadilha que isto tem: biblioteca na fronteira VHDL→Verilog

`neorv32_cfs.vhd` **precisa** morar na biblioteca `neorv32` — o
`neorv32_top` o instancia como `entity neorv32.neorv32_cfs` e não há
escolha. Mas a lógica é Verilog (convenção do projeto para código próprio) e
cai na biblioteca padrão.

O `xelab` não liga um componente VHDL de uma biblioteca a um módulo Verilog
de outra sem ajuda. Ele **não falha**: deixa a instância como caixa preta,
emite um `WARNING` e segue. O firmware então não encontra o coprocessador,
recusa-se a subir, e o sintoma aparece a três camadas de distância da causa.

Duas correções, e a segunda importa mais:

```bash
xelab -L unisims_ver -L neorv32 -L work ...     # a ligação
grep -q "remains a black box" && falhar          # o alarme
```

Um aviso que ninguém lê é um aviso que não existe.

## Espelho: independência de terceiros

O pin por SHA garante **integridade** — o SHA do git é o hash do conteúdo,
então ninguém consegue entregar bytes diferentes sob `b217ead5`. O que ele
não garante é **disponibilidade**: se o upstream apagar a tag ou fizer
force-push, o objeto pode ser coletado e perdemos a capacidade de buscá-lo.

```bash
./scripts/mirror-deps.sh
```

Gera em `build/mirror/` um tarball do código-fonte exato de cada submódulo,
mais `MANIFEST.txt` com URL, tag, commit, tree e SHA-256.

**O artefato é reproduzível:** `git archive` fixa os mtimes pelo commit e
`gzip -n` omite o timestamp do cabeçalho, então rodar duas vezes dá o mesmo
SHA-256. É isso que torna o manifesto verificável por terceiros.

Tamanho: 2,0 MB para o NEORV32. Um `git bundle` com histórico completo daria
**247 MB** — por isso o tarball, e não o bundle.

**Copiar para armazenamento offline** (NAS, backup, anexo de release). Não
commitar: `build/` está no `.gitignore`, e guardar 2 MB de código de terceiros
no repositório anularia o motivo de usar submódulo.

Antes de um release: clone limpo + `git submodule update --init` + rebuild,
confirmando que o resultado reproduz.

## Licença

NEORV32 é **BSD-3-Clause**. Fork, patch, vendorização e redistribuição do
tarball são todos permitidos, mantido o aviso de copyright.
