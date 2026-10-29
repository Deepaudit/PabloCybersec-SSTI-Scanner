"""
payloads.py
-----------
PabloCybersec SSTI Scanner — biblioteca de payloads de DETECÇÃO.

Importante: todo payload aqui serve apenas para CONFIRMAR se uma entrada é
avaliada por um motor de template (ex: ver se "{{7*7}}" vira "49"). Nenhum
payload deste módulo executa comando no sistema operacional do alvo — isso é
proposital. Esta biblioteca é para a etapa de reconhecimento/fingerprint,
não para exploração.

Use somente em alvos para os quais você tem autorização explícita de teste.
"""

from dataclasses import dataclass


@dataclass
class Payload:
    engine: str          # nome do motor de template
    payload: str         # o payload enviado no parâmetro
    expect_contains: str # o que esperamos ver na resposta se a engine for essa
    note: str = ""


# ---------------------------------------------------------------------
# 1) Polyglots de triagem inicial
#    Objetivo: só descobrir "tem alguma coisa avaliando template aqui?"
#    antes de gastar requisições com fingerprint específico.
# ---------------------------------------------------------------------
TRIAGE_POLYGLOTS = [
    # payload bruto                         # o que indicaria avaliação de template
    (r"${{<%[%'\"}}%\\",                     "erro de parsing ou comportamento distinto do baseline"),
    (r"{{7*7}}",                             "49"),
    (r"${7*7}",                              "49"),
    (r"#{7*7}",                              "49"),
    (r"*{7*7}",                              "49"),
    (r"@(7*7)",                              "49"),
    (r"{{7*'7'}}",                           "7777777"),
]


# ---------------------------------------------------------------------
# 2) Payloads diferenciais — usados DEPOIS da triagem confirmar que algo
#    está sendo avaliado, para descobrir qual engine é.
# ---------------------------------------------------------------------
FINGERPRINT_PAYLOADS = [
    Payload("Jinja2 (Python/Flask)",        "{{7*'7'}}",   "7777777",
            "Multiplicação de string é exclusiva de linguagens dinâmicas como Python."),
    Payload("Twig (PHP/Symfony)",           "{{7*7}}",     "49",
            "Confirmar depois que NÃO reage a {{7*'7'}} (Twig não repete string em '*')."),
    Payload("Freemarker (Java)",            "${7*7}",      "49",
            "Sintaxe de interpolação própria do Freemarker."),
    Payload("Velocity (Java)",              "#set($x=7*7)$x", "49",
            "Diretiva #set é exclusiva do Velocity."),
    Payload("Thymeleaf (Java/Spring)",      "*{7*7}",      "49",
            "Expressão de seleção com asterisco é característica do Thymeleaf."),
    Payload("Smarty (PHP)",                 "{7*7}",       "49",
            "Sintaxe de chave simples; cuidado com falso positivo em outras engines."),
    Payload("Razor (.NET)",                 "@(7*7)",      "49",
            "Sintaxe de bloco de código inline do Razor."),
    Payload("ERB (Ruby)",                   "<%= 7*7 %>",  "49",
            "Tag de interpolação ERB clássica do Ruby."),
    Payload("Pug/Jade (Node.js)",           "#{7*7}",      "49",
            "Interpolação de atributo do Pug — pode colidir com Ruby ERB antigo."),
    Payload("Handlebars (Node.js)",         "{{#with 7}}{{this}}{{/with}}", "7",
            "Handlebars normalmente NÃO avalia aritmética — serve para descartar a engine."),
]


# ---------------------------------------------------------------------
# 3) Marcador único — usado para reduzir falso positivo. Em vez de só
#    confiar em "49" (que pode já existir na página por acaso), geramos
#    uma conta cujo resultado é bem específico.
# ---------------------------------------------------------------------
def unique_math_payload(seed: int = 8191):
    """Gera um payload de multiplicação com resultado improvável de já
    existir na página, para reduzir falso positivo no scanner automatizado.
    Retorna (payload_jinja_like, resultado_esperado)."""
    a, b = seed, seed + 2
    result = a * b
    return f"{{{{{a}*{b}}}}}", str(result)


ALL_ENGINES = sorted({p.engine for p in FINGERPRINT_PAYLOADS})
