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
                params.env.ANALYTICS.writeDataPoint({
                    indexes: [params.apiKey || 'anonymous'],

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
