function hashIpToBucket(ip: string): number {
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
        hash = ((hash << 5) - hash) + ip.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash) % 2048;
}

// Fraction of responses to body-sample for ES `meta.db_response_time_ms`.
// Per oxjob #194: gives a passive prod sample of true ES service time per
// request, joinable to the rest of the AE row (URL, api_key, status, total time)
// for shape-vs-cost regression. Sampling keeps the body-read cost bounded.
const ES_TOOK_SAMPLE_RATE = 0.10;

// Cap how much of the body we'll read before giving up on finding
// `meta.db_response_time_ms`. Meta lives near the top of every response, so
// 8 KB is plenty (the IPBES-class 200-result responses are MBs; we don't want
// to buffer those just to grab one number).
const ES_TOOK_PEEK_BYTES = 8192;

async function readEsTookFromBody(resp: Response): Promise<number | null> {
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('application/json')) return null;
    if (!resp.body) return null;
    try {
        const reader = resp.body.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        while (total < ES_TOOK_PEEK_BYTES) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            total += value.byteLength;
        }
        try { await reader.cancel(); } catch { /* ignore */ }
        const text = new TextDecoder().decode(
            chunks.length === 1 ? chunks[0] : (() => {
                const merged = new Uint8Array(total);
                let off = 0;
                for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
                return merged;
            })()
        );
        const m = text.match(/"db_response_time_ms"\s*:\s*(\d+)/);
        return m ? parseInt(m[1], 10) : null;
    } catch {
        return null;
    }
}

export function logAnalytics(params: {
    ctx: ExecutionContext;
    env: { ANALYTICS: AnalyticsEngineDataset };
    apiKey: string | null;
    req: Request;
    url: URL;
    scope: string;
    responseTime: number;
    statusCode: number;
    rateLimit: number;
    rateLimitRemaining: number;
    endpointType?: string;
    creditCost?: number;
    // A cloned upstream response, passed in only on the sampled fraction. We
    // parse `meta.db_response_time_ms` out of it inside ctx.waitUntil so the
    // body-read never blocks the user response.
    responseForEsTook?: Response | null;
}): void {
    params.ctx.waitUntil(
        (async () => {
            try {
                // Build index key with status code for easy filtering
                let userKey: string;
                if (params.apiKey) {
                    userKey = params.apiKey;
                } else {
                    const ip = params.req.headers.get('CF-Connecting-IP') || 'unknown';
                    const bucket = hashIpToBucket(ip);
                    userKey = `anon_${bucket}`;
                }

                // Include status code in index for filtering
                const indexKey = `${userKey}_${params.statusCode}`;

                // -1 sentinel = not sampled or extraction failed. Real ES took is always >= 0.
                // AE queries: WHERE double6 >= 0 to filter to the sampled subset.
                let esTookMs = -1;
                if (params.responseForEsTook) {
                    const v = await readEsTookFromBody(params.responseForEsTook);
                    if (v !== null) esTookMs = v;
                }

                params.env.ANALYTICS.writeDataPoint({
                    indexes: [indexKey],

                    // Blobs: text data (not for aggregation)
                    blobs: [
                        params.apiKey || '',                                      // blob1: API key (empty for anonymous)
                        params.req.headers.get('CF-Connecting-IP') || 'unknown',  // blob2: IP address
                        params.url.pathname + params.url.search,                  // blob3: full URL path
                        params.req.method,                                         // blob4: HTTP method
                        params.scope,                                              // blob5: scope
                        params.req.headers.get('User-Agent') || '',               // blob6: user agent
                        params.req.headers.get('Referer') || '',                  // blob7: referrer
                        params.endpointType || 'unknown'                          // blob8: endpoint type (singleton, list, text, etc.)
                    ],

                    // Doubles: numeric data (for aggregation/math)
                    doubles: [
                        params.responseTime,        // double1: response time (ms)
                        params.statusCode,          // double2: HTTP status
                        params.rateLimit,           // double3: rate limit (credits)
                        params.rateLimitRemaining,  // double4: credits remaining
                        params.creditCost ?? 1,     // double5: credits consumed for this request
                        esTookMs                    // double6: ES `meta.db_response_time_ms` (-1 = not sampled / N/A)
                    ]
                });
            } catch (error) {
                console.error('Analytics write failed:', error);
            }
        })()
    );
}

// Exported for use at the logAnalytics call site: decide whether to clone the
// upstream response for body-sampling. Cheap to call; centralised so the
// sample rate lives in one place.
export function shouldSampleEsTook(): boolean {
    return Math.random() < ES_TOOK_SAMPLE_RATE;
}
