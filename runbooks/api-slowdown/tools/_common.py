"""Shared plumbing for the api-slowdown runbook scripts. Stdlib only.

Credentials: runbooks/api-slowdown/.env (gitignored) — see .env.example. Falls back to the
repo's .dev.vars for ANALYTICS_READ_ONLY_API_KEY so a fresh checkout that already runs
wrangler dev only needs the three ES/account values added.
"""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RUNBOOK_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(RUNBOOK_DIR))
SEARCH_THREADS = 22 * 49  # data nodes × search pool size; the util denominator


def _parse(path):
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.split("  #")[0].strip().strip('"').strip("'")
    return out


ENV = {**_parse(os.path.join(REPO_ROOT, ".dev.vars")), **_parse(os.path.join(RUNBOOK_DIR, ".env"))}


def need(*keys):
    missing = [k for k in keys if not ENV.get(k)]
    if missing:
        raise SystemExit(f"missing {missing} — copy runbooks/api-slowdown/.env.example to .env and fill it in")


def es_client(url):
    """GET/POST helper for an ES URL with embedded basic-auth creds. Returns parsed JSON, or text for _cat."""
    p = urllib.parse.urlsplit(url)
    base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
    hdr = {"Content-Type": "application/json"}
    if p.username:
        hdr["Authorization"] = "Basic " + base64.b64encode(f"{p.username}:{p.password}".encode()).decode()

    def call(path, body=None, timeout=120):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers=hdr, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                t = r.read().decode()
        except urllib.error.HTTPError as e:
            raise SystemExit(f"ES {e.code} on {path}: {e.read().decode()[:400]}")
        try:
            return json.loads(t)
        except ValueError:
            return t
    return call


def walden():
    need("ES_URL_WALDEN")
    return es_client(ENV["ES_URL_WALDEN"])


def monitoring():
    need("ES_URL_MONITORING")
    return es_client(ENV["ES_URL_MONITORING"])


def ae_query(sql):
    """Cloudflare Analytics Engine SQL. Counts are sum(_sample_interval); position() needs IN; no quantile()."""
    need("R2_ACCOUNT_ID", "ANALYTICS_READ_ONLY_API_KEY")
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{ENV['R2_ACCOUNT_ID']}/analytics_engine/sql",
        data=sql.encode(), headers={"Authorization": f"Bearer {ENV['ANALYTICS_READ_ONLY_API_KEY']}"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"AE HTTP {e.code}: {e.read().decode()[:400]}\nSQL: {sql[:300]}")
    if "data" not in d:
        raise SystemExit("AE error (expired token renders as zeros elsewhere — never trust silent 0s): " + json.dumps(d)[:400])
    return d["data"]


def ae_probe():
    """Assert the AE credential works before trusting any result."""
    rows = ae_query("SELECT sum(_sample_interval) AS n FROM openalex_requests_v2 WHERE timestamp > NOW() - INTERVAL '5' MINUTE")
    assert rows and float(rows[0]["n"]) > 0, "AE probe returned nothing"
    return float(rows[0]["n"])


def show(title, rows, limit=40, width=110):
    print(f"\n=== {title} ===")
    if not rows:
        print("(no rows)")
        return rows
    cols = list(rows[0].keys())
    print(" | ".join(cols))
    for r in rows[:limit]:
        print(" | ".join(str(r[c])[:width] for c in cols))
    return rows


def ae_show(title, sql, limit=40):
    return show(title, ae_query(sql), limit)
