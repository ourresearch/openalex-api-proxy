"""Step 3: who is driving it? Cloudflare Analytics Engine, last 60 min. ~2 min.
Rank by response-seconds (sum(double1*_sample_interval)), never by request count.
Schema: blob1 api_key, blob2 ip, blob3 url, blob5 scope (credits/throttle/wide_or), blob6 UA, blob7 referer,
blob8 endpoint type; double1 ms, double2 status, double5 credits, double6 ES took, double7 trustedUi."""
from _common import ae_probe, ae_show

T = "openalex_requests_v2"
print("probe ok, reqs last 5 min:", ae_probe())
ae_show("Timeline last 6h (15-min)", f"""
SELECT toStartOfInterval(timestamp, INTERVAL '15' MINUTE) AS t, sum(_sample_interval) AS reqs,
  sum(if(double2>=500,_sample_interval,0)) AS r5xx, sum(if(double2=429,_sample_interval,0)) AS r429,
  round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms, count(DISTINCT blob2) AS ips, sum(if(blob1='',_sample_interval,0)) AS anon
FROM {T} WHERE timestamp > NOW() - INTERVAL '6' HOUR AND blob8 <> 'health_transition' GROUP BY t ORDER BY t""")
ae_show("Last 60 min vs same window 1/2/3/7 days ago (compare against PRIOR DAYS, never earlier today)", f"""
SELECT toStartOfInterval(timestamp, INTERVAL '1' DAY) AS day, sum(_sample_interval) AS reqs, count(DISTINCT blob2) AS ips,
  sum(if(double2>=500,_sample_interval,0)) AS r5xx, round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms,
  sum(if(blob8='search',_sample_interval,0)) AS search_reqs
FROM {T} WHERE blob8 <> 'health_transition' AND (
  (timestamp > NOW() - INTERVAL '60' MINUTE) OR
  (timestamp > NOW() - INTERVAL '1500' MINUTE AND timestamp < NOW() - INTERVAL '1440' MINUTE) OR
  (timestamp > NOW() - INTERVAL '2940' MINUTE AND timestamp < NOW() - INTERVAL '2880' MINUTE) OR
  (timestamp > NOW() - INTERVAL '4380' MINUTE AND timestamp < NOW() - INTERVAL '4320' MINUTE) OR
  (timestamp > NOW() - INTERVAL '10140' MINUTE AND timestamp < NOW() - INTERVAL '10080' MINUTE))
GROUP BY day ORDER BY day""")
ae_show("Endpoint type last 60 min (total_sec = the cost column)", f"""
SELECT blob8 AS endpoint, sum(_sample_interval) AS reqs, round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms,
  round(sum(double1*_sample_interval)/1000) AS total_sec, sum(if(double2>=500,_sample_interval,0)) AS r5xx
FROM {T} WHERE timestamp > NOW() - INTERVAL '60' MINUTE AND blob8 <> 'health_transition' GROUP BY endpoint ORDER BY total_sec DESC""")
ae_show("Top UAs last 60 min (flat ~10 % shares across many UAs with ~4 req/IP = residential botnet)", f"""
SELECT blob6 AS ua, sum(_sample_interval) AS reqs, count(DISTINCT blob2) AS ips, round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms
FROM {T} WHERE timestamp > NOW() - INTERVAL '60' MINUTE AND blob8 <> 'health_transition' GROUP BY ua ORDER BY reqs DESC LIMIT 15""")
ae_show("Top api_keys by response-seconds, last 60 min (owner lookup: openalex_users.public.api_keys_view)", f"""
SELECT blob1 AS api_key, blob6 AS ua, sum(_sample_interval) AS reqs, round(sum(double1*_sample_interval)/1000) AS total_sec,
  round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms, count(DISTINCT blob2) AS ips,
  sum(if(double2>=500,_sample_interval,0)) AS r5xx, sum(if(double2=429,_sample_interval,0)) AS r429
FROM {T} WHERE timestamp > NOW() - INTERVAL '60' MINUTE AND blob8 <> 'health_transition' GROUP BY api_key, ua ORDER BY total_sec DESC LIMIT 15""")
ae_show("Top IPs by response-seconds, last 60 min", f"""
SELECT blob2 AS ip, blob1 AS api_key, sum(_sample_interval) AS reqs, round(sum(double1*_sample_interval)/1000) AS total_sec,
  round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms, sum(if(double2=429,_sample_interval,0)) AS r429
FROM {T} WHERE timestamp > NOW() - INTERVAL '60' MINUTE AND blob8 <> 'health_transition' GROUP BY ip, api_key ORDER BY total_sec DESC LIMIT 15""")
ae_show("Top URLs by response-seconds, last 60 min", f"""
SELECT blob3 AS url, blob1 AS api_key, sum(_sample_interval) AS reqs, round(sum(double1*_sample_interval)/1000) AS total_sec,
  round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms
FROM {T} WHERE timestamp > NOW() - INTERVAL '60' MINUTE AND blob8 <> 'health_transition' GROUP BY url, api_key ORDER BY total_sec DESC LIMIT 20""")
ae_show("Hourly all-traffic avg_ms, 3 days (put the suspect's hourly counts next to this — the hour-for-hour lock is the proof)", f"""
SELECT toStartOfInterval(timestamp, INTERVAL '1' HOUR) AS h, sum(_sample_interval) AS reqs, round(sum(double1*_sample_interval)/sum(_sample_interval)) AS avg_ms,
  sum(if(double2>=500,_sample_interval,0)) AS r5xx
FROM {T} WHERE timestamp > NOW() - INTERVAL '72' HOUR AND blob8 <> 'health_transition' GROUP BY h ORDER BY h""", limit=80)
ae_show("Search-health ladder transitions last 12h", f"""
SELECT timestamp, blob3 AS transition, double1 AS avg_ms, double2 AS err_pct FROM {T}
WHERE timestamp > NOW() - INTERVAL '12' HOUR AND blob8 = 'health_transition' ORDER BY timestamp DESC LIMIT 40""")
ae_show("wide_or throttle 429s by 10 min, last 3h", f"""
SELECT toStartOfInterval(timestamp, INTERVAL '10' MINUTE) AS m, sum(_sample_interval) AS r429, count(DISTINCT blob1) AS keys
FROM {T} WHERE timestamp > NOW() - INTERVAL '3' HOUR AND blob5='wide_or' GROUP BY m ORDER BY m""")
