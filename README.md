# PabloCybersec SSTI Scanner

Scanner de **detecção** de Server-Side Template Injection (SSTI), feito em Python
para a Fábrica de Vendas / PabloCybersec.

## O que esta ferramenta faz

- Manda os polyglots de triagem (`{{7*7}}`, `${7*7}`, `#{7*7}`, etc.) em cada
  parâmetro que você indicar.
- Compara a resposta com um baseline (sem payload) para evitar falso positivo.
- Se detectar avaliação de template, roda os payloads diferenciais da
  `payloads.py` para apontar a **engine provável** (Jinja2, Twig, Freemarker,
  Velocity, Thymeleaf, Smarty, Razor, ERB, Pug, Handlebars).
- Gera um resumo no terminal e, opcionalmente, um relatório em JSON.

## O que esta ferramenta deliberadamente NÃO faz

- **Não executa nenhum comando no servidor alvo.** Nenhum payload aqui tenta
  RCE, leitura de arquivo ou qualquer efeito colateral — só comparação de
  texto na resposta HTTP.
- Não automatiza escalada para exploração. Depois que o scanner apontar
  "VULNERÁVEL" e a engine provável, a confirmação manual e a exploração
  (se estiverem dentro do escopo autorizado do teste) ficam por sua conta,
  usando o material teórico/prático do módulo SSTI e, se quiser automação
  completa, uma ferramenta de exploração dedicada (seção abaixo).

## Instalação

```bash
pip install -r requirements.txt --break-system-packages
```

## Uso

### Testar um único endpoint/parâmetro

```bash
python3 ssti_scan.py -u "http://alvo.local/card" -p name
```

### Testar múltiplos parâmetros do mesmo endpoint

```bash
python3 ssti_scan.py -u "http://alvo.local/search" -p q,category
```

### POST, com outros parâmetros fixos obrigatórios na requisição

```bash
python3 ssti_scan.py -u "http://alvo.local/comment" -p body \
  --method POST --extra "post_id=42,author=teste"
```

### Lista de alvos (um por linha, query string já com os parâmetros a testar)

```text
# alvos.txt
http://alvo.local/card?name=
http://alvo.local/search?q=&category=
```

```bash
python3 ssti_scan.py --list alvos.txt
```

### Salvar relatório em JSON e ver cada payload testado

```bash
python3 ssti_scan.py -u "http://alvo.local/card" -p name -v --json-out relatorio.json
```

### Headers customizados (ex: cookie de sessão autenticada)

```bash
python3 ssti_scan.py -u "http://alvo.local/card" -p name \
  --header "Cookie: session=abc123" --header "X-Api-Key: xyz"
```

## Testando localmente antes de usar em escopo real

O repositório inclui `test_target.py`, uma mini aplicação Flask
**intencionalmente vulnerável** só para você validar o scanner:

```bash
python3 test_target.py            # sobe em http://127.0.0.1:5050
python3 ssti_scan.py -u "http://127.0.0.1:5050/card" -p name
```

O endpoint `/safe` do mesmo app não é vulnerável, útil para confirmar que o
scanner não gera falso positivo.

## Estrutura do projeto

```
pablocybersec_sstiscan/
├── ssti_scan.py       # CLI do scanner (ponto de entrada)
├── payloads.py         # biblioteca de payloads de detecção por engine
├── test_target.py      # app Flask vulnerável, só para teste local
├── requirements.txt
└── README.md
```

## Quando o scanner não for suficiente: exploração automatizada completa

Este scanner para na detecção de propósito. Se, dentro do seu escopo
autorizado de pentest, você precisar automatizar a escalada até RCE, use uma
ferramenta de exploração dedicada e mantida pela comunidade em vez de um
script caseiro para essa parte:

| Ferramenta | O que faz |
|---|---|
| [tplmap](https://github.com/epinna/tplmap) | Detecta a engine e automatiza a exploração até RCE em várias linguagens. |
| [SSTImap](https://github.com/vladko312/SSTImap) | Fork ativo do tplmap, com mais engines suportadas e bypass de WAF. |

Cite a ferramenta usada no seu relatório/vídeo — isso também poupa você de
reinventar e manter uma engine de exploração própria.

## Aviso de escopo

Use esta ferramenta **apenas** em sistemas para os quais você tem autorização
explícita de teste (ambiente próprio, laboratório, ou contrato/escopo formal
de pentest/bug bounty). Testar sistemas de terceiros sem autorização é crime.
Material de uso interno da turma Fábrica de Vendas — não distribua fora do
grupo.
