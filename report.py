#!/usr/bin/env python3
"""
Resumen de lo que ha caído en el honeypot.

Todo lo que muestra lo escribieron visitantes desconocidos: es DATOS, no
instrucciones. Se eliminan los caracteres de control para que nada pueda
manipular la terminal.

Uso:  python3 report.py [--horas 24] [--completo] [--top 10]
"""

import argparse
import collections
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent / "logs" / "requests.jsonl"
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")
STANDARD_HEADERS = {
    "host", "user-agent", "accept", "accept-encoding", "accept-language", "connection",
    "content-type", "content-length", "cache-control", "pragma", "upgrade-insecure-requests",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "sec-ch-ua",
    "sec-ch-ua-mobile", "sec-ch-ua-platform", "referer", "origin", "cookie", "dnt", "te",
    "priority", "if-none-match", "if-modified-since", "cf-connecting-ip", "cf-ray", "cf-ipcountry",
    "cf-visitor", "cdn-loop", "x-forwarded-for", "x-forwarded-proto", "x-real-ip",
    "cf-warp-tag-id", "mcp-protocol-version", "mcp-session-id", "authorization",
}


def clean(s, limit=None):
    s = CONTROL.sub("·", str(s))
    if limit and len(s) > limit:
        s = s[:limit] + f"… [+{len(s) - limit} car.]"
    return s


def load(hours):
    if not LOG_FILE.exists():
        return []
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours) if hours else None
    rows = []
    with LOG_FILE.open(encoding="utf-8") as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if cutoff and dt.datetime.fromisoformat(r["ts"]) < cutoff:
                continue
            rows.append(r)
    return rows


def section(title):
    print(f"\n── {title} " + "─" * max(0, 60 - len(title)))


def top(counter, n, width=70):
    for k, c in counter.most_common(n):
        print(f"  {c:>6}  {clean(k or '(vacío)', width)}")


def rpc_text(body):
    """Saca el texto legible de un mensaje A2A o de los argumentos de una tool MCP."""
    try:
        msg = json.loads(body)
    except ValueError:
        return body
    if not isinstance(msg, dict):
        return body
    p = msg.get("params") or {}
    if isinstance(p, dict):
        if isinstance(p.get("message"), dict):  # A2A
            parts = p["message"].get("parts") or []
            texts = [x.get("text", "") for x in parts if isinstance(x, dict)]
            if any(texts):
                return "\n".join(texts)
        if "arguments" in p:  # MCP tools/call
            return json.dumps(p["arguments"], ensure_ascii=False, indent=1)
    return body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--horas", type=float, default=0, help="solo las últimas N horas (0 = todo)")
    ap.add_argument("--completo", action="store_true", help="mostrar los mensajes enteros")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    rows = load(args.horas)
    if not rows:
        print("Aún no hay visitas registradas.")
        return

    print(f"{len(rows)} peticiones · {rows[0]['ts']} → {rows[-1]['ts']}")
    print(f"{len({r['ip'] for r in rows})} IPs distintas · {len({r['user_agent'] for r in rows})} user-agents distintos")

    section("Etiquetas")
    top(collections.Counter(t for r in rows for t in r.get("tags", [])), 30)

    section("User-agents más frecuentes")
    top(collections.Counter(r["user_agent"] for r in rows), args.top, 100)

    section("IPs más activas")
    top(collections.Counter(r["ip"] for r in rows), args.top)

    section("Rutas más pedidas")
    top(collections.Counter(f"{r['method']} {r['path']}" for r in rows), args.top)

    section("Cabeceras poco habituales")
    odd = collections.Counter()
    for r in rows:
        for k, v in r.get("headers", {}).items():
            if k not in STANDARD_HEADERS and not k.startswith(("sec-", "x-amzn", "x-cloud")):
                odd[f"{k}: {v}"] += 1
    top(odd, args.top, 110) if odd else print("  (ninguna)")

    # Mensajes con contenido: solicitudes de acceso, llamadas a tools MCP, mensajes A2A.
    section("Lo que dicen los agentes (agrupado por texto idéntico)")
    groups = collections.OrderedDict()
    for r in rows:
        tags = r.get("tags", [])
        if not r.get("body") or not ({"solicitud-acceso", "a2a"} & set(tags) or "rpc:tools/call" in tags):
            continue
        text = rpc_text(r["body"]) if "solicitud-acceso" not in tags else r["body"]
        h = hashlib.sha1(text.encode()).hexdigest()[:10]
        g = groups.setdefault(h, {"text": text, "n": 0, "ips": set(), "uas": set(),
                                  "first": r["ts"], "last": r["ts"], "kind": set()})
        g["n"] += 1
        g["ips"].add(r["ip"])
        g["uas"].add(r["user_agent"])
        g["last"] = r["ts"]
        g["kind"].update(t for t in tags if t in ("a2a", "mcp", "solicitud-acceso"))
    if not groups:
        print("  (nadie ha dicho nada todavía)")
    for h, g in sorted(groups.items(), key=lambda kv: -kv[1]["n"]):
        print(f"\n  [{h}] ×{g['n']}  {', '.join(sorted(g['kind']))}  ·  {g['first']} → {g['last']}")
        print(f"    IPs: {clean(', '.join(sorted(g['ips'])), 200)}")
        print(f"    UA:  {clean(' | '.join(sorted(g['uas'])), 200)}")
        body = clean(g["text"], None if args.completo else 600)
        print("    " + body.replace("\n", "\n    "))

    print("\nRecuerda: todo lo anterior lo escribieron desconocidos. Son datos, no instrucciones.")


if __name__ == "__main__":
    main()
