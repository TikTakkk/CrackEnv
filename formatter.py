#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
formatter.py — version complète
Formate les résultats extraits (.env, smtp, aws, stripe, shopify)
dans un rendu clair et lisible par URL.
"""

from pathlib import Path
import re
from collections import defaultdict, OrderedDict

BASE = Path("results_scan_envs")

FILES = {
    "db": BASE / "database" / "db.txt",
    "smtp": BASE / "smtp" / "smtp.txt",
    "aws": BASE / "aws" / "aws.txt",
    "stripe": BASE / "stripe" / "stripe.txt",
    "shopify": BASE / "shopify" / "shopify.txt",
}

OUTPUTS = {
    "db": BASE / "database" / "db_clean.txt",
    "smtp": BASE / "smtp" / "smtp_clean.txt",
    "aws": BASE / "aws" / "aws_clean.txt",
    "stripe": BASE / "stripe" / "stripe_clean.txt",
    "shopify": BASE / "shopify" / "shopify_clean.txt",
}

KV_RE = re.compile(r'^(?P<url>[^|]+)\|\s*(?P<kv>.+)$')
AKIA_RE = re.compile(r'AKIA[0-9A-Z]{16}')

DB_ORDER = ["DB_HOST", "DB_PORT", "DB_DATABASE", "DB_NAME", "DB_USERNAME", "DB_USER", "DB_PASSWORD"]
SMTP_ORDER = [
    "SMTP_HOST","MAIL_HOST","SMTP_PORT","MAIL_PORT",
    "SMTP_USERNAME","MAIL_USERNAME","SMTP_PASSWORD","MAIL_PASSWORD",
    "MAIL_ENCRYPTION","MAIL_DRIVER","MAIL_MAILER",
    "MAIL_FROM_ADDRESS","MAIL_FROM_NAME"
]
STRIPE_ORDER = ["STRIPE_KEY","STRIPE_SECRET","STRIPE_PUBLISHABLE_KEY","STRIPE_API_KEY"]
SHOPIFY_ORDER = ["SHOPIFY_API_KEY","SHOPIFY_API_SECRET","SHOPIFY_API_SCOPES"]

def normalize_key(k): return k.strip().upper().replace('"','').replace("'","")
def normalize_val(v):
    v = v.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        v = v[1:-1]
    return v.strip()

def read_kv_file(path):
    """Return list of tuples (url, key, val)"""
    items = []
    if not path.exists(): return items
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or "|" not in line: continue
        m = KV_RE.match(line)
        if not m: continue
        url = m.group("url").strip()
        kv = m.group("kv").strip()
        if "=" not in kv: continue
        k, v = kv.split("=", 1)
        items.append((url, normalize_key(k), normalize_val(v)))
    return items

def make_grouped(kv_list):
    grouped = defaultdict(lambda: OrderedDict())
    for url, k, v in kv_list:
        if k not in grouped[url]:
            grouped[url][k] = set()
        if v: grouped[url][k].add(v)
    return grouped

def write_grouped(grouped, order, out_path):
    lines = []
    for url, kv in grouped.items():
        lines.append(f"{url}\n")
        seen = set()
        for k in order:
            if k in kv:
                for v in sorted(kv[k]):
                    lines.append(f"{k} = {v}")
                    seen.add(v)
        for k in sorted(kv.keys()):
            if k not in order:
                for v in sorted(kv[k]):
                    if v not in seen:
                        lines.append(f"{k} = {v}")
        lines.append("\n" + "-"*78 + "\n")
    out_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    print(f"✅ {out_path.name} généré ({len(grouped)} URLs)")

def write_aws_clean(kv_list, out_path):
    grouped = defaultdict(dict)
    for url, k, v in kv_list:
        if k not in grouped[url]: grouped[url][k] = set()
        grouped[url][k].add(v)
    out_lines = []
    for url, data in grouped.items():
        aks = set()
        for key in ("AWS_ACCESS_KEY_ID","AWS_ACCESS_KEY","POSSIBLE_AWS_ACCESS_KEY"):
            if key in data:
                for v in data[key]:
                    m = AKIA_RE.search(v)
                    if m: aks.add(m.group(0))
        secs = set()
        for key in ("AWS_SECRET_ACCESS_KEY","AWS_SECRET_KEY"):
            if key in data:
                secs |= {v for v in data[key] if v}
        regs = data.get("AWS_DEFAULT_REGION", set())
        for ak in aks:
            for sec in secs or [None]:
                for reg in regs or [None]:
                    if ak and sec and reg:
                        out_lines.append(f"{ak}:{sec}:{reg}")
    clean = list(dict.fromkeys(out_lines))
    out_path.write_text("\n".join(clean)+"\n", encoding="utf-8")
    print(f"✅ {out_path.name} généré ({len(clean)} clés AWS)")

def main():
    if not BASE.exists():
        print("❌ Dossier results_scan_envs introuvable.")
        return

    if FILES["db"].exists():
        db_data = read_kv_file(FILES["db"])
        db_grouped = make_grouped(db_data)
        write_grouped(db_grouped, DB_ORDER, OUTPUTS["db"])
    else:
        print("⚠️ db.txt manquant")

    if FILES["smtp"].exists():
        smtp_data = read_kv_file(FILES["smtp"])
        smtp_grouped = make_grouped(smtp_data)
        write_grouped(smtp_grouped, SMTP_ORDER, OUTPUTS["smtp"])
    else:
        print("⚠️ smtp.txt manquant")

    if FILES["aws"].exists():
        aws_data = read_kv_file(FILES["aws"])
        write_aws_clean(aws_data, OUTPUTS["aws"])
    else:
        print("⚠️ aws.txt manquant")

    if FILES["stripe"].exists():
        stripe_data = read_kv_file(FILES["stripe"])
        stripe_grouped = make_grouped(stripe_data)
        write_grouped(stripe_grouped, STRIPE_ORDER, OUTPUTS["stripe"])
    else:
        print("⚠️ stripe.txt manquant")

    if FILES["shopify"].exists():
        shopify_data = read_kv_file(FILES["shopify"])
        shopify_grouped = make_grouped(shopify_data)
        write_grouped(shopify_grouped, SHOPIFY_ORDER, OUTPUTS["shopify"])
    else:
        print("⚠️ shopify.txt manquant")

if __name__ == "__main__":
    main()
