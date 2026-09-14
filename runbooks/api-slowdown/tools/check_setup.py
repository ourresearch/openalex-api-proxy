"""Setup check: can this machine reach everything the runbook needs? Run first on a new machine.
Each line is PASS/WARN/FAIL with what to fix. Exit 1 if any FAIL. Read-only everywhere."""
import json
import os
import shutil
import subprocess
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import ENV, RUNBOOK_DIR, REPO_ROOT, es_client, ae_query

results = []


def report(status, name, detail, fix=""):
    results.append(status)
    print(f"[{status:4s}] {name:34s} {detail}" + (f"\n        fix: {fix}" if fix and status != "PASS" else ""))


def redact(url):
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.username or '?'}:***@{p.hostname}" + (f":{p.port}" if p.port else "")


# 1. credential file present
env_path = os.path.join(RUNBOOK_DIR, ".env")
if os.path.exists(env_path):
    report("PASS", ".env file", env_path)
else:
    report("FAIL", ".env file", "missing", f"cp {os.path.join(RUNBOOK_DIR, '.env.example')} {env_path} and fill in the values")

# 2. each key present
for k, where in [("ES_URL_WALDEN", ".env"), ("ES_URL_MONITORING", ".env"), ("R2_ACCOUNT_ID", ".env"),
                 ("ANALYTICS_READ_ONLY_API_KEY", ".env (or the repo .dev.vars)")]:
    if ENV.get(k):
        report("PASS", f"{k} set", redact(ENV[k]) if k.startswith("ES_URL") else f"{len(ENV[k])} chars")
    else:
        report("FAIL", f"{k} set", "empty", f"add {k}=... to {where}")

# 3. production ES: health + the indices the scripts assume + node stats permission
if ENV.get("ES_URL_WALDEN"):
    try:
        es = es_client(ENV["ES_URL_WALDEN"])
        h = es("/_cluster/health", timeout=30)
        report("PASS", "prod ES reachable", f"status={h['status']} nodes={h['number_of_nodes']} data={h['number_of_data_nodes']}")
        idx = es("/_cat/indices/works-v*?h=index,docs.count&s=index", timeout=30).strip().splitlines()
        report("PASS" if idx else "FAIL", "works index present", ", ".join(l.split()[0] for l in idx) or "no works-v* index",
               "es_live.py / es_replay assume works-v34 — update the index name in the scripts if it was reindexed")
        ns = es("/_nodes/stats/indices/search?filter_path=nodes.*.indices.search.query_total", timeout=30)
        report("PASS", "node stats readable", f"{len(ns.get('nodes', {}))} nodes (needed for shard-qps)")
        t = es("/_tasks?actions=indices:data/read/search&detailed=true&group_by=none", timeout=30)
        report("PASS", "tasks API readable", f"{len(t.get('tasks', []))} in-flight searches (needed for query shapes)")
    except SystemExit as e:
        report("FAIL", "prod ES reachable", str(e)[:160], "check ES_URL_WALDEN creds; the user needs monitor/read on the cluster")
    except Exception as e:
        report("FAIL", "prod ES reachable", f"{type(e).__name__}: {e}"[:160], "network/DNS? VPN not required; Elastic Cloud is public")

# 4. monitoring ES: slowlog data stream + metricbeat docs, both recent
if ENV.get("ES_URL_MONITORING"):
    try:
        mon = es_client(ENV["ES_URL_MONITORING"])
        h = mon("/_cluster/health", timeout=30)
        report("PASS", "monitoring ES reachable", f"status={h['status']} nodes={h['number_of_nodes']}")
        r = mon("/.ds-elastic-cloud-logs-8-*/_search", {"size": 0, "query": {"bool": {"filter": [
            {"term": {"event.dataset": "elasticsearch.index_search_slowlog"}}, {"range": {"@timestamp": {"gte": "now-6h"}}}]}}}, timeout=60)
        n = r["hits"]["total"]["value"]
        report("PASS" if n else "WARN", "slowlog shipping", f"{n} slowlog entries in the last 6h",
               "0 can be a genuinely quiet cluster; if the cluster is busy, filebeat→monitoring shipping is broken")
        r = mon("/.ds-.monitoring-es-8-mb-*/_search", {"size": 0, "query": {"bool": {"filter": [
            {"term": {"elasticsearch.index.name": "works-v34"}}, {"range": {"@timestamp": {"gte": "now-30m"}}}]}}}, timeout=60)
        n = r["hits"]["total"]["value"]
        report("PASS" if n else "FAIL", "metricbeat index stats", f"{n} works-v34 docs in the last 30 min (needed by es_prior_day_compare)",
               "metricbeat→monitoring shipping stopped, or the index was renamed")
    except SystemExit as e:
        report("FAIL", "monitoring ES reachable", str(e)[:160], "check ES_URL_MONITORING; password was last reset in the Elastic Cloud UI (openalex-prod-monitoring)")
    except Exception as e:
        report("FAIL", "monitoring ES reachable", f"{type(e).__name__}: {e}"[:160])

# 5. Analytics Engine: probe AND a schema-touching query (an expired token can render as zeros elsewhere)
if ENV.get("R2_ACCOUNT_ID") and ENV.get("ANALYTICS_READ_ONLY_API_KEY"):
    try:
        rows = ae_query("SELECT sum(_sample_interval) AS n, count(DISTINCT blob8) AS endpoint_types FROM openalex_requests_v2 WHERE timestamp > NOW() - INTERVAL '5' MINUTE")
        n = float(rows[0]["n"]) if rows else 0
        report("PASS" if n > 0 else "FAIL", "Analytics Engine", f"{n:,.0f} requests in the last 5 min, {rows[0]['endpoint_types'] if rows else 0} endpoint types",
               "0 rows with no error = wrong account id or the proxy stopped logging; an auth error = bad/expired token (use the read-only API key, not the wrangler OAuth token)")
    except SystemExit as e:
        report("FAIL", "Analytics Engine", str(e)[:200], "ANALYTICS_READ_ONLY_API_KEY needs Account Analytics:Read on the Our Research account; R2_ACCOUNT_ID must be that account")

# 6. levers: Heroku CLI auth (users DB for rate_throttled) and psql
heroku = shutil.which("heroku")
if heroku:
    try:
        who = subprocess.run([heroku, "auth:whoami"], capture_output=True, text=True, timeout=20)
        if who.returncode == 0:
            report("PASS", "heroku CLI auth", who.stdout.strip())
            cfg = subprocess.run([heroku, "config:get", "DATABASE_URL", "-a", "openalex-users-api"], capture_output=True, text=True, timeout=30)
            ok = cfg.returncode == 0 and cfg.stdout.startswith("postgres")
            report("PASS" if ok else "FAIL", "users-api DATABASE_URL", "readable" if ok else cfg.stderr.strip()[:120],
                   "you need collaborator access to the openalex-users-api Heroku app for the rate_throttled lever")
        else:
            report("WARN", "heroku CLI auth", who.stderr.strip()[:120] or "not logged in", "heroku login — only needed for the rate_throttled lever, diagnosis works without it")
    except Exception as e:
        report("WARN", "heroku CLI auth", f"{type(e).__name__}: {e}"[:120])
else:
    report("WARN", "heroku CLI", "not installed", "brew install heroku/brew/heroku — only needed for the rate_throttled lever")
psql = shutil.which("psql") or (os.path.exists("/opt/homebrew/opt/libpq/bin/psql") and "/opt/homebrew/opt/libpq/bin/psql")
report("PASS" if psql else "WARN", "psql", psql or "not found", "brew install libpq; it lives in /opt/homebrew/opt/libpq/bin (not on PATH by default)")

# 7. wrangler (for FORCE_HEALTH_STATE / secrets) — informational
wr = shutil.which("wrangler") or (os.path.exists(os.path.join(REPO_ROOT, "node_modules", ".bin", "wrangler")) and "node_modules/.bin/wrangler")
report("PASS" if wr else "WARN", "wrangler", wr or "not found", "npm install in the repo root — only needed to set FORCE_HEALTH_STATE / Worker secrets")

fails = results.count("FAIL"); warns = results.count("WARN")
print(f"\n{results.count('PASS')} pass, {warns} warn, {fails} fail — " + ("ready: diagnosis scripts will work" if not fails else "fix the FAILs above before relying on the scripts"))
sys.exit(1 if fails else 0)
