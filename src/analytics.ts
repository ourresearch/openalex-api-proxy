function hashIpToBucket(ip: string): number {
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
        hash = ((hash << 5) - hash) + ip.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash) % 2048;
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
                        params.creditCost ?? 1      // double5: credits consumed for this request
                    ]
                });
            } catch (error) {
                console.error('Analytics write failed:', error);
            }
        })()
    );
}
