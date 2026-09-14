"""Who sends >10-term OR-lists on the wide filter fields (last 60 min), and would the throttle bind on them?"""
import urllib.parse
from collections import Counter
from _common import ae_query

T = "openalex_requests_v2"; WIDE = ("topics.id", "primary_topic.id", "concepts.id", "concept.id")
rows = []
for fld in WIDE:
    rows += ae_query(f"SELECT blob3, blob1, blob2, blob6, double2, _sample_interval FROM {T} WHERE timestamp > NOW() - INTERVAL '60' MINUTE AND position('{fld}' IN blob3) > 0 LIMIT 10000")

def wide_terms(url):
    best = 0
    for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(urllib.parse.unquote(url)).query, keep_blank_values=True):
        if k != "filter": continue
        for c in v.split(","):
            i = c.find(":")
            if i < 0: continue
            f, t = c[:i].strip().lower(), c[i + 1:].strip()
            if f in WIDE and not t.startswith("!"):
                best = max(best, len(set(x.strip().lower() for x in t.split("|") if x.strip())))
    return best

over, under, actors, sizes = Counter(), Counter(), Counter(), Counter()
for r in rows:
    n = wide_terms(r["blob3"]); w = float(r["_sample_interval"]); st = int(float(r["double2"]))
    if n > 10: over[st] += w; actors[(r["blob1"][:8] or "anon", r["blob2"], r["blob6"][:40])] += w; sizes[n] += w
    elif n > 0: under[st] += w
print(f"sampled rows: {len(rows)}")
print(">10 wide OR terms, by status:", {k: round(v) for k, v in over.items()})
print("1–10 wide OR terms, by status:", {k: round(v) for k, v in under.items()})
print("term-count distribution (>10):", sorted((k, round(v)) for k, v in sizes.items())[:15])
print("actors sending >10-term wide ORs (reqs/hr; the throttle binds only above ~3,600/hr sustained):")
for k, v in actors.most_common(10): print("  ", k, round(v))
