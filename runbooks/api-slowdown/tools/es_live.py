"""Step 1b: live shard-qps × ms/query = utilization, per-index load, in-flight query shapes. ~1 min, read-only."""
import random, re, time
from collections import Counter
from _common import walden, SEARCH_THREADS

es = walden()

def sample():
    ns = es("/_nodes/stats/indices/search?filter_path=nodes.*.indices.search")["nodes"].values()
    return (sum(n["indices"]["search"]["query_total"] for n in ns),
            sum(n["indices"]["search"]["query_time_in_millis"] for n in ns),
            sum(n["indices"]["search"]["query_current"] for n in ns))

br = es("/_nodes/stats/breaker?filter_path=nodes.*.breakers.parent.tripped")["nodes"].values()
print("parent circuit-breaker trips (lifetime):", sum(n["breakers"]["parent"]["tripped"] for n in br))
t0 = time.time(); a = sample(); time.sleep(30); b = sample(); dt = time.time() - t0
dq, dms = b[0] - a[0], b[1] - a[1]
util = dms / 1000 / dt / SEARCH_THREADS * 100
print(f"LIVE 30s: shard-qps={dq/dt:,.0f}  ms/shard-query={dms/max(dq,1):.1f}  thread-s/s={dms/1000/dt:,.0f}  util≈{util:.0f}%  query_current={b[2]}")
print("reference: baseline 13,000 qps × 27 ms = 33 %; afternoon 40–46 %; knee ≈85 %; 08-24 ran ~100 %, 09-14 peak 76 %")

def idx_sample():
    st = es("/_stats/search?level=indices&filter_path=indices.*.total.search.query_total,indices.*.total.search.query_time_in_millis")
    return {k: (v["total"]["search"]["query_total"], v["total"]["search"]["query_time_in_millis"]) for k, v in st["indices"].items()}
i0 = idx_sample(); time.sleep(20); i1 = idx_sample()
print("\nPER-INDEX (20 s sample):")
rows = [(k, (i1[k][0] - i0[k][0]) / 20, (i1[k][1] - i0[k][1]) / 1000 / 20) for k in i1 if k in i0]
for k, qps, ts in sorted(rows, key=lambda r: -r[2])[:8]:
    print(f"  {k:18s} shard-qps={qps:8,.0f}  thread-s/s={ts:6.1f}  ms/q={ts*1000/max(qps,0.01):.1f}")

tasks = es("/_tasks?actions=indices:data/read/search&detailed=true&group_by=none")
tl = list(tasks.get("tasks", []))
print(f"\nIN-FLIGHT top-level search tasks: {len(tl)}")
shape, idx, ages = Counter(), Counter(), []
KW = ["function_score", "query_string", "multi_match", "match_phrase", "fuzz", "wildcard", "prefix", "aggregations",
      "topics.id.lower", "raw_affiliation_strings", "knn", "script_score"]
for t in tl:
    d = t.get("description", "")
    m = re.match(r"indices\[([^\]]*)\]", d); idx[m.group(1) if m else "?"] += 1
    ages.append(t.get("running_time_in_nanos", 0) / 1e9)
    keys = [kw for kw in KW if kw in d]
    if d.count("topics.id.lower") >= 20: keys.append(f"WIDE-OR×{d.count('topics.id.lower')}")
    shape[",".join(keys) or "plain filter/sort"] += 1
print("by index:", idx.most_common(8))
ages.sort(reverse=True)
if ages: print(f"age p50/p90/max s: {ages[len(ages)//2]:.2f}/{ages[len(ages)//10]:.2f}/{ages[0]:.2f}")
print("shape mix:"); [print(f"  {n:4d}  {s}") for s, n in shape.most_common(12)]
print("\nOLDEST in-flight (rank suspects by rate × cost, not by this list alone):")
for t in sorted(tl, key=lambda t: -t.get("running_time_in_nanos", 0))[:5]:
    print(f"  {t.get('running_time_in_nanos',0)/1e9:.1f}s  {t.get('description','')[:500]}\n")
random.seed(1)
print("RANDOM sample:")
for t in random.sample(tl, min(4, len(tl))): print("  ", t.get("description", "")[:400], "\n")
