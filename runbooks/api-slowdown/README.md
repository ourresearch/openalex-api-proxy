# Runbook: "the API is slow" (Elasticsearch search-pool saturation)

Written after the 2026-08-24 (botnet × uncached bootstrap fan-out) and 2026-09-14 (one prepaid
key's 425-term `topics.id` OR-list) incidents — oxjob #876 has the narratives. Every step below
is a script in `tools/`, stdlib-only Python 3.11+, read-only against ES and Cloudflare.

## Setup (once per machine)
```
cp runbooks/api-slowdown/.env.example runbooks/api-slowdown/.env   # then fill in the 4 values
```
`ES_URL_WALDEN` / `ES_URL_MONITORING` are the Elastic Cloud URLs with basic-auth creds embedded
(same values as the openalex-walden `.env`). `ANALYTICS_READ_ONLY_API_KEY` is picked up from the
repo's `.dev.vars` if you already have that. The wrangler OAuth token is NOT a substitute: it
expires every ~8 h and an expired token renders as a clean table of zeros.

## The recipe
| step | script | what it answers | time |
|---|---|---|---|
| 1a | `tools/es_health.py` | Is ES saturated? nodes at `49/49` search threads, queues, CPU, tombstones | 10 s |
| 1b | `tools/es_live.py` | **shard-qps × ms/query = utilization**; per-index load; in-flight query shapes and the oldest ones | 1 min |
| 2 | `tools/es_prior_day_compare.py [HH:MM]` | Is this level normal for the hour? Same window 1/2/7 days ago | 30 s |
| 3 | `tools/ae_attribution.py` | Who? Top keys/IPs/URLs by **response-seconds**, UA-share uniformity, hourly latency, ladder transitions | 2 min |
| 4 | `tools/slowlog.py [min]` | Confirm the shape: slow-log census by query shape | 30 s |
| 5 | `tools/ae_wide_or_census.py` | Who is sending long OR-lists on wide fields; would the throttle bind on them | 1 min |
| 7 | `tools/es_replay_slowlog_query.py <needle>` | Quantify a shape before designing a rule (quiet cluster only) | 2 min |

Reading the numbers:
- Healthy: 0 nodes at 49/49, queue 0, ms/shard-query 25–40, util ≤ 45 % (afternoon weekdays
  run 40–46 %). Saturated: most of the 22 data nodes at 49/49, queues in the hundreds, util ≥ 70 %.
  The knee is ~85 %; past it latency runs away even as offered load falls (08-24 went to ~100 %).
- **Shard-qps normal + ms/query high ⇒ a heavy shape** (09-14: 12.6K qps at 65 ms). **Shard-qps
  doubled + ms/query normal ⇒ volume or fan-out** (08-24). Edge request counts can stay flat
  through both — one request is 72 shard queries.
- Rank actors by response-seconds. The 09-14 actor was 1 % of requests and 4× the next actor's
  cost. In-flight share is biased toward whatever is slowest; rank by rate × cost.
- Compare against prior days at the same hour, never against earlier the same day.
- **Prove it before acting**: the suspect's hourly request count next to hourly all-traffic
  avg_ms. If the spikes line up hour for hour, act.

## Levers, cheapest first
| lever | where | effect | revert |
|---|---|---|---|
| `rate_throttled=true` on the user | users Postgres: `heroku config:get DATABASE_URL -a openalex-users-api`; psql in `/opt/homebrew/opt/libpq/bin` | 1 req/s gate on all the user's keys (`throttle:user:` DO); live in ≤60 s (key cache) | same statement, `false` |
| wide-OR throttle | `WIDE_OR_FILTER_FIELDS` / `WIDE_OR_MAX_TERMS` in `src/endpointClassifier.ts` | automatic 1 req/s on >10-term topics/concepts OR-lists; 429s carry `blob5='wide_or'` | edit, push |
| boolean-search throttle | `src/index.ts` (>5 OR/AND/NOT in search text) | 1/5/25 req/s by tier | — |
| `FORCE_HEALTH_STATE` | Worker env | pin the anon ladder to ORANGE/RED (keyless `search` only) | unset |
| edge-cache a constant endpoint | `src/index.ts` | removes an endpoint from ES entirely (08-24 fix) | revert commit |
| dyno restart | Heroku `openalex-api` | clears H12-stuck workers; transient | — |

Do NOT: put a Cloudflare Managed Challenge on the API (breaks the GUI's CORS preflight; rejected
2026-07-04) · lower the anon per-second cap (diffuse load is sub-1/s per IP) · trust in-flight
share or request counts as cost.

## Known gaps (oxjob #876 PLAN)
No alert fires on search-thread saturation — both incidents were found by a person. The general
form of the 09-14 fix is a scheduled per-key response-seconds budget that flips `rate_throttled`
automatically; when that exists it belongs next to these scripts, or as a Worker cron with
`ES_URL_WALDEN` as a Worker secret (`wrangler secret put`, set `CLOUDFLARE_ACCOUNT_ID` first).
