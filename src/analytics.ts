function hashIpToBucket(ip: string): number {
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
        hash = ((hash << 5) - hash) + ip.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash) % 1024;
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
}): void {
    params.ctx.waitUntil(
        (async () => {
            try {
                // For anonymous users, hash their IP into 1024 buckets
                let indexKey: string;
                if (params.apiKey) {
                    indexKey = params.apiKey;
                } else {
                    const ip = params.req.headers.get('CF-Connecting-IP') || 'unknown';
                    const bucket = hashIpToBucket(ip);
                    indexKey = `anon_${bucket}`;
                }

                params.env.ANALYTICS.writeDataPoint({
                    indexes: [indexKey],

                    // Blobs: text data (not for aggregation)
                    blobs: [
                        params.req.headers.get('CF-Connecting-IP') || 'unknown',  // blob1: IP address
                        params.url.pathname + params.url.search,                  // blob2: full URL path
                        params.req.method,                                         // blob3: HTTP method
                        params.scope                                               // blob4: scope
                    ],

                    // Doubles: numeric data (for aggregation/math)
                    doubles: [
                        params.responseTime,        // double1: response time (ms)
                        params.statusCode,          // double2: HTTP status
                        params.rateLimit,           // double3: rate limit
                        params.rateLimitRemaining   // double4: tokens remaining
                    ]
                });
            } catch (error) {
                console.error('Analytics write failed:', error);
            }
        })()
    );
}
