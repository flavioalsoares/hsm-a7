# Código de terceiros e propriedade intelectual

Este arquivo existe para responder, sem que ninguém precise perguntar, a
duas coisas: **de quem é cada pedaço de código que não é nosso**, e **se há
alguma restrição sobre o que o projeto implementa**.

---

## Componentes de terceiros

Nenhum deles é *vendorizado*: os três entram como **submódulos git**
apontando para o repositório original, fixados por tag ou por SHA de commit.
Este repositório **não redistribui** o código deles — quem clona busca
direto na fonte.

| Componente | Origem | Licença | Fixado em |
|---|---|---|---|
| NEORV32 | `github.com/stnolting/neorv32` | BSD-3-Clause | tag `v1.13.3` |
| AES | `github.com/secworks/aes` | BSD-2-Clause | commit `80dc471` |
| SHA-256 | `github.com/secworks/sha256` | BSD-2-Clause | commit `837c5cc` |

Copyright dos cores de cripto: Joachim Strömbergson (2013, 2014).
Copyright do NEORV32: Stephan Nolting e contribuidores.

As três licenças são permissivas e compatíveis entre si e com qualquer
licença permissiva que este projeto adote. Todas exigem preservar o aviso de
copyright — o que a estrutura de submódulo faz sozinha, já que os arquivos
`LICENSE` originais vêm junto.

### Modificações

Duas, ambas no `sha256`, ambas de temporização, ambas em `patches/`:

```
patches/sha256/0001-w-mem-registrado.patch
patches/sha256/0002-k-constants-registrado.patch
```

Cada patch declara no cabeçalho a origem, o commit do upstream e o motivo.
Eles são **aplicados sobre uma cópia** em `build/patched/` por
`scripts/apply-patches.sh`; `third_party/` permanece byte a byte igual ao
upstream, e o script falha se não estiver. Ver `doc/submodulos.md`.

A BSD-2-Clause permite modificar e redistribuir mantendo o aviso de
copyright, que os arquivos modificados preservam.

---

## Algoritmos — todos livres de royalties

Tudo que este projeto implementa é norma pública e sem encargo de patente
para implementar:

| Algoritmo | Norma | Situação |
|---|---|---|
| AES (Rijndael) | FIPS 197 | liberado sem royalties pelos autores — era condição do concurso do NIST |
| SHA-256 | FIPS 180-4 | livre |
| HMAC | RFC 2104 | as patentes existentes eram de licenciamento livre e já expiraram |
| CMAC | SP 800-38B | livre |
| CTR_DRBG | SP 800-90A | livre |
| Health tests RCT/APT | SP 800-90B | livre |
| Key blocks TR-31 / X9.143 | ANSI | norma; implementar não tem encargo |

E os que aparecem **só na documentação**, sem implementação aqui:

| Assunto | Situação |
|---|---|
| DES / 3DES | patentes dos anos 1970, expiradas há décadas |
| PIN blocks | ISO 9564 |
| DUKPT | ANSI X9.24-1 e X9.24-3 |

### A distinção que costuma confundir

**O texto da norma é protegido por direito autoral; o algoritmo dentro dela
não é uma restrição de uso.** A ANSI vende o X9.24-3; a ISO vende a 9564.
Comprar o documento para lê-lo é uma coisa; *implementar* o que ele descreve
não infringe nada.

O que não se pode fazer é **redistribuir o texto** da norma. Este projeto
não o faz: a documentação descreve estrutura e motivação, cita a norma como
fonte, e manda o leitor buscá-la. É também por isso que os layouts exatos de
bytes de PIN block **não** estão escritos aqui.

---

## Marcas

A documentação deste projeto **não nomeia fabricante nem produto de HSM**. O
modelo de referência é a *categoria* — HSM de pagamento — e não há vínculo,
patrocínio, endosso nem alegação de compatibilidade com equipamento
comercial algum.

Aparecem, e são coisa diferente:

- **Nomes de norma e de organismo** — ISO, ANSI, NIST, PCI, EMV. São a
  fonte, e citá-la é o oposto de um problema.
- **Nomes de método consagrados na literatura e usados pelas próprias
  normas** — IBM 3624, PVV. São terminologia; trocá-los por perífrase
  tornaria o texto ininteligível.
- **Citações acadêmicas** — Bond, Zieliński, Clulow, e o caso histórico da
  IBM CCA que eles estudaram. Descrever vulnerabilidade publicada, datada e
  já corrigida é o conteúdo normal de literatura de segurança, e o texto a
  usa para explicar *por que a defesa existe* — nunca em tempo presente e
  nunca como juízo sobre produto atual.

Nada disto é reivindicação de compatibilidade nem crítica a produto.

---

## Ferramentas

Usadas para construir, não incorporadas ao resultado: AMD Vivado, GCC para
RISC-V, picolibc, openFPGALoader, pandoc. Cada uma sob a própria licença; o
projeto não redistribui nenhuma.

Os **vetores de teste** vêm do NIST (CAVP) e do IETF, com URL e SHA-256
registrados em `vectors/MANIFEST.txt`. São publicações de governo e de
organismo de padronização, feitas para exatamente este uso.
