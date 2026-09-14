"""Step 4: slow-log shape census from the monitoring cluster (query slowlog, warn ≥2 s, one entry per shard).
usage: slowlog.py [minutes back, default 60]"""
import json, sys
from collections import Counter
from _common import monitoring

mon = monitoring(); mins = int(sys.argv[1]) if len(sys.argv) > 1 else 60
r = mon("/.ds-elastic-cloud-logs-8-*/_search", {"size": 2000, "_source": ["event.duration", "elasticsearch.slowlog.source", "elasticsearch.index.name"],
     "query": {"bool": {"filter": [{"term": {"event.dataset": "elasticsearch.index_search_slowlog"}}, {"range": {"@timestamp": {"gte": f"now-{mins}m"}}}]}},
     "sort": [{"event.duration": "desc"}]})
hits = r["hits"]["hits"]
print(f"slowlog entries last {mins} min (≥2 s, per shard): {r['hits']['total']['value']} (capped at 10k); classifying top {len(hits)} by duration")

def flat(d, pre=""):
    o = {}
    for k, v in d.items():
        o.update(flat(v, pre + k + ".")) if isinstance(v, dict) else o.__setitem__(pre + k, v)
    return o

shape, dur, idx, topicN = Counter(), Counter(), Counter(), Counter()
for h in hits:
    s = flat(h["_source"]); src = s.get("elasticsearch.slowlog.source") or ""
    d = s.get("event.duration", 0) / 1e9; idx[s.get("elasticsearch.index.name")] += 1
    try: txt = json.dumps(json.loads(json.loads('"' + src + '"')))   # source is double-escaped
    except Exception: txt = src
    n = txt.count("topics.id.lower")
    if n >= 20: k = "WIDE OR-list on topics.id (≥20 terms)"; topicN[n] += 1
    elif "raw_affiliation_strings.keyword" in txt: k = "RAS verifier (users-api, works alias)"
    elif "function_score" in txt and ("query_string" in txt or "wildcard" in txt): k = "relevance search w/ query_string/wildcard"
    elif "function_score" in txt: k = "relevance search (function_score)"
    elif "aggregations" in txt: k = "group_by aggregation"
    else: k = "other filter/sort"
    shape[k] += 1; dur[k] += d
print("by index:", idx.most_common(5))
print("\nSHAPES (entries, slow-seconds, avg):")
for k, n in shape.most_common(): print(f"  {n:5d}  {dur[k]:8.0f}s  avg {dur[k]/n:4.1f}s  {k}")
if topicN: print("wide-OR term counts:", topicN.most_common(5))
print("\nslowest 3:")
for h in hits[:3]:
    s = flat(h["_source"]); print(f"  {s.get('event.duration',0)/1e9:.1f}s {s.get('elasticsearch.index.name')} {(s.get('elasticsearch.slowlog.source') or '')[:220]}")
