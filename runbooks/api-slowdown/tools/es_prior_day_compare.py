"""Step 2: is this load normal for the hour? works-v34 shard-qps / ms/query / util for a 10-min window
today vs the same window 1, 2 and 7 days ago, from the monitoring cluster's metricbeat docs.
usage: es_prior_day_compare.py [HH:MM UTC window start, default = 12 min ago]"""
import datetime, sys
from _common import monitoring, walden, SEARCH_THREADS

mon = monitoring(); es = walden()

def window(start, minutes=10, index="works-v34"):
    end = start + datetime.timedelta(minutes=minutes)
    body = {"size": 0, "query": {"bool": {"filter": [{"term": {"elasticsearch.index.name": index}},
            {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]}},
            "aggs": {"q0": {"min": {"field": "elasticsearch.index.total.search.query_total"}},
                     "q1": {"max": {"field": "elasticsearch.index.total.search.query_total"}},
                     "t0": {"min": {"field": "elasticsearch.index.total.search.query_time_in_millis"}},
                     "t1": {"max": {"field": "elasticsearch.index.total.search.query_time_in_millis"}},
                     "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                     "n": {"value_count": {"field": "@timestamp"}}}}
    r = mon("/.ds-.monitoring-es-8-mb-*/_search", body)["aggregations"]
    if not r["n"]["value"]: return None
    secs = (r["last"]["value"] - r["first"]["value"]) / 1000 or 1
    dq = r["q1"]["value"] - r["q0"]["value"]; dt = r["t1"]["value"] - r["t0"]["value"]
    return dq / secs, dt / max(dq, 1), dt / 1000 / secs

now = datetime.datetime.now(datetime.timezone.utc).replace(second=0, microsecond=0)
if len(sys.argv) > 1:
    hh, mm = map(int, sys.argv[1].split(":")); start = now.replace(hour=hh, minute=mm)
else:
    start = now - datetime.timedelta(minutes=12)
print(f"works-v34, 10-min window starting {start.strftime('%H:%M')} UTC")
print(f"{'':16s} {'shard-qps':>10s} {'ms/query':>9s} {'thread-s/s':>11s} {'util':>6s}")
for label, s in [("today", start), ("yesterday", start - datetime.timedelta(days=1)),
                 ("2 days ago", start - datetime.timedelta(days=2)), ("7 days ago", start - datetime.timedelta(days=7))]:
    w = window(s)
    print(f"{label:16s} {w[0]:10,.0f} {w[1]:9.1f} {w[2]:11,.0f} {w[2]/SEARCH_THREADS*100:5.0f}%" if w else f"{label:16s} (no metricbeat docs)")
tp = es("/_cat/thread_pool/search?h=node_name,active,queue")
data = [l.split() for l in tp.strip().splitlines() if l.startswith("instance") and len(l.split()) == 3]
act = [int(r[1]) for r in data]; qu = [int(r[2]) for r in data]
print(f"\nES pool now: nodes at 49/49 = {sum(1 for a in act if a >= 49)}/{len(data)}, max active={max(act) if act else 0}, total queue={sum(qu)}")
