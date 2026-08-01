# Vetores de teste conhecidos (KAT)

Estes números são a **autoridade** do projeto. A regra inviolável nº 5 do
`CLAUDE.md` depende inteiramente deles:

> Se um KAT falha, o bug está no código, não no vetor. Não ajustar vetor,
> não relaxar assert, não marcar teste como skip.

Essa regra só vale se a procedência do vetor for verificável. Por isso nada
aqui foi escrito de memória ou gerado por este projeto — tudo vem das fontes
oficiais, com hash registrado em `MANIFEST.txt`.

## Conteúdo

| Diretório | Origem | O que cobre |
|---|---|---|
| `aes/` | NIST CAVP (AESAVS) | AES-256 ECB e CBC, cifra e decifra |
| `sha/` | NIST CAVP (SHAVS) | SHA-256, mensagens curtas e longas |
| `hmac/` | IETF RFC 4231 | HMAC-SHA-256 |
| `drbg/` | NIST CAVP (SP 800-90A) | CTR_DRBG com AES-256 |

### Os quatro tipos de vetor do AESAVS

Vale entender por que são quatro arquivos e não um, porque cada um pega uma
classe diferente de defeito:

- **GFSbox** — textos escolhidos para exercitar caminhos específicos da
  S-box, com chave zero.
- **KeySbox** — o inverso: chaves escolhidas, texto zero.
- **VarKey** — varre **cada bit da chave** ligado isoladamente. São 256
  vetores para AES-256. Pega erro de indexação na expansão de chave.
- **VarTxt** — varre **cada bit do bloco** ligado isoladamente, 128 vetores.
  Pega erro de ordem de byte, de rotação e de permutação.

Um core que passa nos quatro dificilmente tem erro estrutural. Um que passa
só no GFSbox pode ter a expansão de chave inteira errada.

## Verificar

```bash
./scripts/fetch-vectors.sh --check    # confere o que está no repositório
./scripts/fetch-vectors.sh            # baixa das fontes e reextrai
```

O script recusa arquivo cujo hash não bate com o do manifesto. Rodar sem
`--check` sobre um repositório limpo termina sem nenhuma diferença — os
vetores versionados são byte a byte os do NIST e da IETF.

## Por que estão versionados

Ao contrário dos outros artefatos derivados deste projeto, os vetores vão
para o repositório. Dois motivos:

1. **Os testes precisam rodar offline.** Um POST que depende de rede não é
   um POST.
2. **Congelam a referência.** O NIST reorganiza URLs; um vetor no
   repositório com hash conhecido continua verificável mesmo se o link
   quebrar. É o mesmo raciocínio do espelho de submódulos
   (`scripts/mirror-deps.sh`).

## Uso

| Consumidor | Fase | Como |
|---|---|---|
| `sim/tb/tb_aes_kat.v` | 2 | lê `.rsp` em simulação, contra o core |
| `sim/tb/tb_sha256_kat.v` | 2 | idem |
| `sim/tb/tb_hmac_kat.v` | 2 | HMAC em firmware sobre o core de SHA |
| POST no firmware | 2 | subconjunto embutido na imagem |

O mesmo vetor rodando em simulação **e** no POST é diagnóstico: se passa no
testbench e falha no POST, o problema está no barramento ou na integração,
não no núcleo criptográfico.
