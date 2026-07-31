# patches/

Correções em código de terceiros ficam aqui como arquivos `.patch` aplicados
pelo build — **nunca** editadas direto em `third_party/`.

Uma edição direta no submódulo não é guardada em lugar nenhum deste
repositório, é descartada em silêncio por `git submodule update`, e não existe
num clone novo. Além disso quebra a procedência: o pin continua dizendo
`v1.13.3` enquanto o bitstream contém outra coisa.

Nomear como `NNNN-alvo-descricao.patch`, gerado com `git format-patch` ou
`git diff` a partir do submódulo limpo.

**Vazio de propósito.** Não há nenhuma modificação nos cores externos, e o
caminho da Fase 2 (substituir o CFS na lista de arquivos do build) também não
precisa de patch.

Antes de adicionar o primeiro, ler `doc/submodulos.md` — a escada de decisão
coloca patch só no degrau 2, e configuração via wrapper resolve a maioria dos
casos.
