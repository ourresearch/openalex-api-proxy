"""Step 7: replay a real slow-log query with controlled variants to find what makes it slow.
Run on a QUIET cluster only — each variant is a real 72-shard query. Edit VARIANTS for the shape at hand.
usage: es_replay_slowlog_query.py <substring that identifies the shape in the slowlog source> [minutes back]"""
import copy, json, sys
from _common import monitoring, walden

needle = sys.argv[1] if len(sys.argv) > 1 else "topics.id.lower"; mins = int(sys.argv[2]) if len(sys.argv) > 2 else 120
mon = monitoring(); es = walden()
r = mon("/.ds-elastic-cloud-logs-8-*/_search", {"size": 600, "_source": ["elasticsearch.slowlog.source", "event.duration"],
     "query": {"bool": {"filter": [{"term": {"event.dataset": "elasticsearch.index_search_slowlog"}}, {"range": {"@timestamp": {"gte": f"now-{mins}m"}}}]}},
     "sort": [{"event.duration": "desc"}]})
src = None
for h in r["hits"]["hits"]:
    s = h["_source"]["elasticsearch"]["slowlog"]["source"]
    if needle in s:
        src = json.loads(json.loads('"' + s + '"')); break
if not src: raise SystemExit(f"no slowlog source containing {needle!r} in the last {mins} min")
q = copy.deepcopy(src); q.pop("search_after", None); q["from"] = 0; q["timeout"] = "30s"
print("shape keys:", list(q.keys()), "| size", q.get("size"), "| track_total_hits", q.get("track_total_hits"))

def run(label, body, n=2):
    tooks = []; total = None
    for _ in range(n):
        res = es("/works-v34/_search", body); tooks.append(res["took"]); total = res["hits"]["total"]
    print(f"{label:55s} took={tooks} ms  total={total}")

def find_should(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "should" and isinstance(v, list) and len(v) >= 10 and all("term" in x for x in v): return v
            f = find_should(v)
            if f: return f
    elif isinstance(node, list):
        for v in node:
            f = find_should(v)
            if f: return f

run("A. original", q)
b = copy.deepcopy(q); b["track_total_hits"] = 10000; run("B. track_total_hits=10000", b)
b = copy.deepcopy(q); b["size"] = 25; run("C. size 25", b)
sh = find_should(q)
if sh:
    for n in (50, 25, 10, 1):
        if len(sh) > n:
            b = copy.deepcopy(q); s2 = find_should(b); del s2[n:]; run(f"D. first {n} OR terms", b)
    b = copy.deepcopy(q); s2 = find_should(b); vals = [list(x["term"].values())[0]["value"] for x in s2]; fld = list(s2[0]["term"].keys())[0]
    s2[:] = [{"terms": {fld: vals}}]; run("E. same terms as ONE terms query", b)
    ids = [h["_id"] for h in es("/works-v34/_search", {"size": len(sh), "_source": False, "query": {"match_all": {}}})["hits"]["hits"]]
    b = copy.deepcopy(q); s2 = find_should(b); s2[:] = [{"term": {"ids.openalex": {"value": i}}} for i in ids]; run(f"F. control: {len(ids)} OR'd ids.openalex", b)
run("G. control: plain 1-source list, size 25", {"size": 25, "query": {"bool": {"filter": [{"term": {"is_xpac": {"value": "false"}}},
    {"term": {"primary_location.source.id.lower": {"value": "https://openalex.org/S137773608"}}}]}}, "sort": q.get("sort"), "track_total_hits": 2147483647})
