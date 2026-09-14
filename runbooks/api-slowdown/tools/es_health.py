"""Step 1a: cluster health, per-node CPU/heap, search thread pool, index tombstones. ~10 s, read-only."""
import datetime, json
from _common import walden

es = walden()
print("UTC now:", datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S"))
h = es("/_cluster/health")
print("HEALTH:", json.dumps({k: h[k] for k in ["status", "number_of_nodes", "number_of_data_nodes", "active_shards",
      "relocating_shards", "initializing_shards", "unassigned_shards", "number_of_pending_tasks", "task_max_waiting_in_queue_millis"]}))
print("\nNODES (sorted by cpu):")
print(es("/_cat/nodes?v&h=name,node.role,cpu,load_1m,load_5m,heap.percent,ram.percent,disk.used_percent,uptime&s=cpu:desc"))
print("SEARCH THREAD POOL (healthy: active well under 49, queue 0):")
print(es("/_cat/thread_pool/search?v&h=node_name,active,queue,rejected,completed,size&s=active:desc"))
print("PENDING TASKS:", (es("/_cat/pending_tasks?v") or "").strip() or "(none)")
print("\nINDICES (docs.deleted / docs.count = tombstone share; works-v34 was 23 % on 08-24, 28 % on 09-14):")
print(es("/_cat/indices/works*,authors*,institutions*,sources*,funders*,publishers*,topics*,keywords*?v&h=index,health,pri,rep,docs.count,docs.deleted,store.size,segments.count&s=index"))
print("MERGES:", es("/_cat/nodes?h=name,merges.current&s=merges.current:desc").split("\n")[0])
