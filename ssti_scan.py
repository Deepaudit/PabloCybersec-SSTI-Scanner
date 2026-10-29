#!/usr/bin/env python3
"""
PabloCybersec SSTI Scanner
===========================
Scanner de DETECÇÃO de Server-Side Template Injection.

O que ele faz:
  1. Pega um baseline (resposta normal, sem payload).
  2. Envia os polyglots de triagem em cada parâmetro informado.
  3. Se algum polyglot evidenciar avaliação de template (ex: 49 aparecendo
     onde antes não aparecia nada), roda os payloads de fingerprint para
     tentar identificar a engine provável.
  4. Reporta um veredito: VULNERÁVEL (com engine provável) / SUSPEITO /
     NÃO DETECTADO.

O que ele NUNCA faz:
  - Não executa comando no servidor alvo.
  - Não tenta ler arquivo, variável de ambiente ou dado interno do alvo.
  - Não automatiza escalada para RCE. Isso é deliberado: esta é uma
    ferramenta de reconhecimento, não de exploração.

Uso típico (alvo e escopo SEMPRE autorizados por você):
  python3 ssti_scan.py -u "http://alvo.local/card" -p name
  python3 ssti_scan.py -u "http://alvo.local/search" -p q,category --method POST
  python3 ssti_scan.py --list alvos.txt

Formato do --list (um alvo por linha):
  http://alvo.local/card?name=
  http://alvo.local/search?q=&category=
"""

import argparse
import sys
import time
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] Este scanner depende de 'requests'. Instale com:")
    print("    pip install requests --break-system-packages")
    sys.exit(1)

from payloads import TRIAGE_POLYGLOTS, FINGERPRINT_PAYLOADS, unique_math_payload

BANNER = r"""
  ____       _     _       ____      _                     
 |  _ \ __ _| |__ | | ___ / ___|   _| |__   ___ _ __ ___  ___  ___
 | |_) / _` | '_ \| |/ _ \ |  | | | | '_ \ / _ \ '__/ __|/ _ \/ __|
 |  __/ (_| | |_) | | (_) | |__| |_| | |_) |  __/ |  \__ \  __/ (__
 |_|   \__,_|_.__/|_|\___/\____\__, |_.__/ \___|_|  |___/\___|\___|
                                |___/
            SSTI SCANNER — detecção, não exploração
"""


@dataclass
class ScanResult:
    url: str
    param: str
    method: str
    status: str                 # "VULNERAVEL" | "SUSPEITO" | "NAO_DETECTADO" | "ERRO"
    engine_provavel: Optional[str] = None
    evidencia: list = field(default_factory=list)
    erro: Optional[str] = None


def build_request(base_url: str, param: str, value: str, method: str, other_params: dict):
    params = dict(other_params)
    params[param] = value
    if method.upper() == "GET":
        return {"url": base_url, "params": params}
    else:
        return {"url": base_url, "data": params}


def send(session, base_url, param, value, method, other_params, timeout):
    req = build_request(base_url, param, value, method, other_params)
    try:
        if method.upper() == "GET":
            r = session.get(req["url"], params=req["params"], timeout=timeout)
        else:
            r = session.post(req["url"], data=req["data"], timeout=timeout)
        return r.text, None
    except requests.RequestException as e:
        return None, str(e)


def scan_param(session, base_url, param, other_params, method, timeout, verbose):
    # 1) baseline
    baseline_text, err = send(session, base_url, param, "pablocybersec_baseline_9f3a", method, other_params, timeout)
    if err:
        return ScanResult(base_url, param, method, "ERRO", erro=err)

    evidencia = []
    triggered_triage = False

    # 2) triagem com polyglots
    for payload, expect in TRIAGE_POLYGLOTS:
        text, err = send(session, base_url, param, payload, method, other_params, timeout)
        if err:
            continue
        if expect in text and expect not in baseline_text:
            evidencia.append(f"Polyglot '{payload}' -> apareceu '{expect}' na resposta (ausente no baseline).")
            triggered_triage = True
        if verbose:
            print(f"    [triagem] payload={payload!r} -> {'match' if expect in text else 'sem match'}")
        time.sleep(0.05)

    # 3) confirmação com marcador único (reduz falso positivo)
    uniq_payload, uniq_expect = unique_math_payload()
    text, err = send(session, base_url, param, uniq_payload, method, other_params, timeout)
    unique_confirmed = False
    if not err and uniq_expect in text and uniq_expect not in baseline_text:
        unique_confirmed = True
        evidencia.append(f"Marcador único '{uniq_payload}' -> resultado '{uniq_expect}' confirmado na resposta.")

    if not triggered_triage and not unique_confirmed:
        return ScanResult(base_url, param, method, "NAO_DETECTADO", evidencia=evidencia)

    # 4) fingerprint de engine
    engine_hits = []
    for fp in FINGERPRINT_PAYLOADS:
        text, err = send(session, base_url, param, fp.payload, method, other_params, timeout)
        if err:
            continue
        if fp.expect_contains in text and fp.expect_contains not in baseline_text:
            engine_hits.append(fp.engine)
            evidencia.append(f"[{fp.engine}] payload={fp.payload!r} confirmou '{fp.expect_contains}'. {fp.note}")
        if verbose:
            print(f"    [fingerprint] {fp.engine}: payload={fp.payload!r} -> {'match' if fp.expect_contains in text else 'sem match'}")
        time.sleep(0.05)

    if engine_hits:
        engine_provavel = engine_hits[0] if len(engine_hits) == 1 else " / ".join(sorted(set(engine_hits)))
        return ScanResult(base_url, param, method, "VULNERAVEL", engine_provavel=engine_provavel, evidencia=evidencia)
    else:
        return ScanResult(base_url, param, method, "SUSPEITO", evidencia=evidencia)


def parse_target_line(line: str):
    """Aceita formato: http://host/path?param1=&param2=val"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parsed = urllib.parse.urlsplit(line)
    base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params = {k: (v[0] if v else "") for k, v in qs.items()}
    return base_url, params


def main():
    ap = argparse.ArgumentParser(
        description="PabloCybersec SSTI Scanner — detecção de SSTI sem exploração.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("-u", "--url", help="URL base do endpoint (ex: http://alvo.local/card)")
    ap.add_argument("-p", "--params", help="Parâmetro(s) a testar, separados por vírgula (ex: name,q)")
    ap.add_argument("--extra", help="Outros parâmetros fixos no formato k=v,k2=v2 (necessários para a requisição funcionar)", default="")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET", help="Método HTTP (default: GET)")
    ap.add_argument("--list", help="Arquivo com uma URL por linha (query string já contendo os parâmetros a testar)")
    ap.add_argument("--timeout", type=float, default=8.0, help="Timeout por requisição em segundos (default: 8)")
    ap.add_argument("--json-out", help="Salvar relatório em JSON neste caminho")
    ap.add_argument("-v", "--verbose", action="store_true", help="Mostrar cada payload testado")
    ap.add_argument("--header", action="append", default=[], help="Header extra, formato 'Nome: valor' (pode repetir)")
    args = ap.parse_args()

    if not args.url and not args.list:
        ap.error("informe --url/--params ou --list")

    print(BANNER)
    print("[*] Esta ferramenta apenas detecta e identifica a engine provável.")
    print("[*] Nenhum payload executa comando no alvo. Use só em escopo autorizado.\n")

    session = requests.Session()
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            session.headers[k.strip()] = v.strip()

    targets = []  # lista de (base_url, param, other_params, method)

    if args.url:
        other_params = {}
        if args.extra:
            for kv in args.extra.split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    other_params[k] = v
        params = [p.strip() for p in (args.params or "").split(",") if p.strip()]
        if not params:
            ap.error("--params é obrigatório quando --url é usado")
        for p in params:
            targets.append((args.url, p, other_params, args.method))

    if args.list:
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_target_line(line)
                if not parsed:
                    continue
                base_url, params = parsed
                for p in params.keys():
                    other = {k: v for k, v in params.items() if k != p}
                    targets.append((base_url, p, other, args.method))

    results = []
    for base_url, param, other_params, method in targets:
        print(f"[>] Testando {method} {base_url}  parâmetro='{param}'")
        res = scan_param(session, base_url, param, other_params, method, args.timeout, args.verbose)
        results.append(res)
        if res.status == "VULNERAVEL":
            print(f"    [VULNERÁVEL] engine provável: {res.engine_provavel}")
        elif res.status == "SUSPEITO":
            print(f"    [SUSPEITO] template parece avaliar algo, engine não confirmada")
        elif res.status == "ERRO":
            print(f"    [ERRO] {res.erro}")
        else:
            print(f"    [ok] nada detectado")
        print()

    # resumo
    print("=" * 60)
    print("RESUMO")
    print("=" * 60)
    vulns = [r for r in results if r.status == "VULNERAVEL"]
    suspects = [r for r in results if r.status == "SUSPEITO"]
    print(f"Testados: {len(results)}  |  Vulneráveis: {len(vulns)}  |  Suspeitos: {len(suspects)}")
    for r in vulns:
        print(f"  [CRÍTICO] {r.method} {r.url} :: param='{r.param}' :: engine={r.engine_provavel}")
    for r in suspects:
        print(f"  [REVISAR] {r.method} {r.url} :: param='{r.param}'")

    if args.json_out:
        out = [r.__dict__ for r in results]
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"\n[*] Relatório salvo em {args.json_out}")


if __name__ == "__main__":
    main()
