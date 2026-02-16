import { Client } from "pg";
import { RateLimiter } from "./rateLimiter";
import { logAnalytics } from "./analytics";
import { classifyEndpoint, EndpointClassification } from "./endpointClassifier";

export interface Env {
    HYPERDRIVE: Hyperdrive;
    openalex_db: D1Database;  // Keep for rollback - remove after Hyperdrive verified
    RATE_LIMITER: DurableObjectNamespace;
    ANALYTICS: AnalyticsEngineDataset;
    OPENALEX_API_URL: string;
    TEXT_API_URL: string;
    SEARCH_API_URL?: string;  // Optional - falls back to OPENALEX_API_URL if not set
    CONTENT_WORKER: Fetcher;  // Service binding to openalex-content-worker
}

// In-memory cache for API key validation
const API_KEY_CACHE = new Map<string, {
    valid: boolean;
    maxPerDay?: number;
    maxCreditsPerDay?: number;
    isGrandfathered?: boolean;
    onetimeCreditsBalance?: number;
    onetimeCreditsExpiresAt?: string;
    error?: string;
    cachedAt: number;
}>();
const CACHE_TTL = 60000; // 60 seconds

export { RateLimiter };

export default {
    async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        const startTime = Date.now();

        if (req.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: getCorsHeaders()
            });
        }

        if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "POST") {
            return addCorsHeaders(new Response("Method Not Allowed", { status: 405 }));
        }

        const url = new URL(req.url);

        const apiKey = getApiKeyFromRequest(req);
        let hasValidApiKey = false;
        // TODO Feb 13, 2026: Change these to 100 to require API key for normal usage.
        // 2026-01-26: Reduced from 100K to 10K during API slowdown incident to shift capacity to API key holders.
        // With list=1 credit, users can make 10K list requests/day without an API key.
        let maxPerDay = 10000;  // Default daily rate limit for unauthenticated users
        let maxCreditsPerDay = 10000;  // Default credits for unauthenticated users (1:1)
        let isGrandfathered = false;  // Unauthenticated users are not grandfathered

        let onetimeCreditsBalance = 0;
        let onetimeCreditsExpiresAt: string | undefined;

        if (apiKey) {
            const authResult = await checkApiKey(req, env);
            if (!authResult.valid) {
                // Log invalid API key attempts for security monitoring
                console.warn("Invalid API key attempt", {
                    invalidKey: apiKey,
                    ip: req.headers.get("CF-Connecting-IP"),
                    path: url.pathname,
                    error: authResult.error,
                    userAgent: req.headers.get("User-Agent")
                });

                const errorResponse = json(401, {
                    error: "Invalid or missing API key",
                    message: authResult.error || "Provide a valid API key"
                });

                // Log 401 error
                logAnalytics({
                    ctx,
                    env,
                    apiKey,
                    req,
                    url,
                    scope: 'credits',
                    responseTime: Date.now() - startTime,
                    statusCode: 401,
                    rateLimit: 0,
                    rateLimitRemaining: 0
                });

                return errorResponse;
            }
            hasValidApiKey = true;
            maxPerDay = authResult.maxPerDay ?? 100000;
            maxCreditsPerDay = authResult.maxCreditsPerDay ?? maxPerDay;
            isGrandfathered = authResult.isGrandfathered || false;
            onetimeCreditsBalance = authResult.onetimeCreditsBalance ?? 0;
            onetimeCreditsExpiresAt = authResult.onetimeCreditsExpiresAt;

            // Trigger writeback of consumed one-time credits on cache refresh (non-blocking)
            if (authResult.cacheRefreshed && onetimeCreditsBalance > 0) {
                const wbRateLimitKey = `credits:${apiKey}`;
                ctx.waitUntil(
                    writebackOnetimeCredits(env, apiKey, wbRateLimitKey, maxCreditsPerDay, onetimeCreditsBalance)
                );
            }
        }

        const protectedParamCheck = checkProtectedParams(url, hasValidApiKey);
        if (!protectedParamCheck.valid) {
            const errorResponse = json(403, {
                error: "Forbidden",
                message: protectedParamCheck.error
            });

            // Log 403 error
            logAnalytics({
                ctx,
                env,
                apiKey,
                req,
                url,
                scope: 'main',
                responseTime: Date.now() - startTime,
                statusCode: 403,
                rateLimit: 0,
                rateLimitRemaining: 0
            });

            return errorResponse;
        }

        // Handle /rate-limit endpoint
        const normalizedPath = url.pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
        if (normalizedPath === 'rate-limit') {
            return await handleRateLimitEndpoint(req, env, apiKey, hasValidApiKey, maxCreditsPerDay, isGrandfathered, onetimeCreditsBalance, onetimeCreditsExpiresAt);
        }

        // Classify endpoint and determine credit cost
        const classification = classifyEndpoint(url.pathname, url.searchParams);
        const creditCost = classification.creditCost;

        // Use unified credits-based rate limiting
        const scope = "credits";
        const identifier = apiKey || req.headers.get("CF-Connecting-IP") || "anon";
        const rateLimitKey = `${scope}:${identifier}`;
        const limit = maxCreditsPerDay;

        // Check rate limit using Durable Object
        const id = env.RATE_LIMITER.idFromName(rateLimitKey);
        const limiter = env.RATE_LIMITER.get(id);

        let rateLimitResult: {
            success: boolean;
            retryAfter?: number;
            remaining?: number;
            onetimeRemaining?: number;
            limitType?: 'per_second' | 'daily';
            creditsUsed?: number;
            creditsRequired?: number;
            fromOnetime?: boolean;
        };

        try {
            rateLimitResult = await limiter.fetch("http://internal/check", {
                method: "POST",
                body: JSON.stringify({ dailyLimit: limit, perSecondLimit: 100, credits: creditCost, onetimeBalance: onetimeCreditsBalance })
            }).then(res => res.json());
        } catch (error) {
            // If DO fails, allow the request through but log the error
            console.error("Rate limiter DO error:", error);
            rateLimitResult = { success: true, remaining: limit, creditsUsed: creditCost, onetimeRemaining: onetimeCreditsBalance };
        }

        // Handle rate limit exceeded
        if (!rateLimitResult.success) {
            const isPerSecond = rateLimitResult.limitType === 'per_second';
            let message: string;
            if (isPerSecond) {
                message = `Rate limit exceeded: 100 requests per second. Please slow down.`;
            } else if (onetimeCreditsBalance > 0) {
                message = `Insufficient credits. This request requires ${creditCost} credits but you have ${rateLimitResult.remaining} daily and ${rateLimitResult.onetimeRemaining ?? 0} purchased credits remaining. Daily credits reset at midnight UTC. Buy more at https://openalex.org/pricing`;
            } else {
                message = `Insufficient credits. This request requires ${creditCost} credits but you only have ${rateLimitResult.remaining} remaining. Resets at midnight UTC. Need more? Buy credits at https://openalex.org/pricing`;
            }

            const errorResponse = new Response(JSON.stringify({
                error: "Rate limit exceeded",
                message,
                retryAfter: rateLimitResult.retryAfter,
                creditsRequired: creditCost,
                creditsRemaining: rateLimitResult.remaining,
                onetimeCreditsRemaining: rateLimitResult.onetimeRemaining ?? 0
            }), {
                status: 429,
                headers: {
                    "Content-Type": "application/json",
                    "Retry-After": Math.ceil(rateLimitResult.retryAfter || 1).toString(),
                    "X-RateLimit-Limit": limit.toString(),
                    "X-RateLimit-Remaining": (rateLimitResult.remaining ?? 0).toString(),
                    "X-RateLimit-Onetime-Remaining": (rateLimitResult.onetimeRemaining ?? 0).toString(),
                    "X-RateLimit-Credits-Required": creditCost.toString(),
                    "X-RateLimit-Reset": getSecondsUntilMidnightUTC().toString(),
                    ...Object.fromEntries(getCorsHeaders())
                }
            });

            // Log 429 error
            logAnalytics({
                ctx,
                env,
                apiKey,
                req,
                url,
                scope,
                responseTime: Date.now() - startTime,
                statusCode: 429,
                rateLimit: limit,
                rateLimitRemaining: rateLimitResult.remaining ?? 0,
                endpointType: classification.type,
                creditCost
            });

            return errorResponse;
        }

        // Route content.openalex.org/* OR /content/* to content worker
        const isContentRequest = url.hostname === 'content.openalex.org' || /^\/content(\/|$)/i.test(url.pathname);

        if (isContentRequest) {
            // Normalize path: content.openalex.org/works/X → /works/X for content worker
            // api.openalex.org/content/X → /X for content worker (strip /content prefix)
            const contentPath = url.hostname === 'content.openalex.org'
                ? url.pathname
                : url.pathname.replace(/^\/content/, '');

            // Content downloads require an API key (but allow root docs endpoint)
            const isContentDownload = /^\/works\//i.test(contentPath);
            if (isContentDownload && !hasValidApiKey) {
                return json(401, {
                    error: "API key required",
                    message: "Content downloads require an API key. Get one free at https://openalex.org/users"
                });
            }

            const contentUrl = new URL(req.url);
            contentUrl.pathname = contentPath;
            const contentReq = new Request(contentUrl, req);

            const contentResponse = await env.CONTENT_WORKER.fetch(contentReq);

            // Check if content worker returned a different credit cost (e.g., 1 for 404)
            const actualCostHeader = contentResponse.headers.get("X-Credits-Cost");
            const actualCost = actualCostHeader ? parseInt(actualCostHeader, 10) : creditCost;
            let adjustedRemaining = rateLimitResult.remaining ?? 0;

            // Refund credits if actual cost < charged cost
            let adjustedOnetimeRemaining = rateLimitResult.onetimeRemaining ?? 0;
            if (actualCost < creditCost) {
                const refundAmount = creditCost - actualCost;
                try {
                    const refundResult = await limiter.fetch("http://internal/refund", {
                        method: "POST",
                        body: JSON.stringify({ dailyLimit: limit, credits: refundAmount, onetimeBalance: onetimeCreditsBalance })
                    }).then(res => res.json() as Promise<{ remaining: number; onetimeRemaining: number }>);
                    adjustedRemaining = refundResult.remaining;
                    adjustedOnetimeRemaining = refundResult.onetimeRemaining;
                } catch (error) {
                    console.error("Failed to refund credits:", error);
                }
            }

            // Add rate limit headers to the response
            const newHeaders = new Headers(contentResponse.headers);
            newHeaders.delete("X-Credits-Cost"); // Remove internal header
            newHeaders.set("X-RateLimit-Limit", limit.toString());
            newHeaders.set("X-RateLimit-Remaining", adjustedRemaining.toString());
            newHeaders.set("X-RateLimit-Onetime-Remaining", adjustedOnetimeRemaining.toString());
            newHeaders.set("X-RateLimit-Credits-Used", actualCost.toString());
            newHeaders.set("X-RateLimit-Reset", getSecondsUntilMidnightUTC().toString());

            const finalResponse = addCorsHeaders(new Response(contentResponse.body, {
                status: contentResponse.status,
                statusText: contentResponse.statusText,
                headers: newHeaders
            }));

            // Log analytics with actual cost
            logAnalytics({
                ctx,
                env,
                apiKey,
                req,
                url,
                scope,
                responseTime: Date.now() - startTime,
                statusCode: contentResponse.status,
                rateLimit: limit,
                rateLimitRemaining: adjustedRemaining,
                endpointType: classification.type,
                creditCost: actualCost
            });

            return finalResponse;
        }

        const targetApiUrl = getTargetApiUrl(url, env);

        const forwardPath = getForwardPath(url, targetApiUrl, env);

        const openalexUrl = new URL(targetApiUrl + forwardPath);

        url.searchParams.forEach((value, key) => {
            openalexUrl.searchParams.set(key, value);
        });

        // For POST requests, we need to clone the request to preserve the body
        const proxyHeaders = new Headers({
            "User-Agent": "OpenAlex-Proxy/1.0",
            "Accept": req.headers.get("Accept") || "application/json",
            "Accept-Encoding": req.headers.get("Accept-Encoding") || ""
        });

        // Only add Content-Type for POST requests
        if (req.method === "POST") {
            proxyHeaders.set("Content-Type", req.headers.get("Content-Type") || "application/json");
        }

        const proxyReq = new Request(openalexUrl.toString(), {
            method: req.method,
            headers: proxyHeaders,
            body: req.method === "POST" ? await req.clone().arrayBuffer() : undefined
        });

        const response = await fetch(proxyReq);

        // Return response with rate limit headers (credits-based)
        const newHeaders = new Headers(response.headers);
        newHeaders.set("X-RateLimit-Limit", limit.toString());
        newHeaders.set("X-RateLimit-Remaining", (rateLimitResult.remaining ?? 0).toString());
        newHeaders.set("X-RateLimit-Onetime-Remaining", (rateLimitResult.onetimeRemaining ?? 0).toString());
        newHeaders.set("X-RateLimit-Credits-Used", creditCost.toString());
        newHeaders.set("X-RateLimit-Reset", getSecondsUntilMidnightUTC().toString());

        const finalResponse = addCorsHeaders(new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders
        }));

        // Log analytics for successful requests
        logAnalytics({
            ctx,
            env,
            apiKey,
            req,
            url,
            scope,
            responseTime: Date.now() - startTime,
            statusCode: response.status,
            rateLimit: limit,
            rateLimitRemaining: rateLimitResult.remaining ?? 0,
            endpointType: classification.type,
            creditCost
        });

        return finalResponse;
    }
} satisfies ExportedHandler<Env>;


function getApiKeyFromRequest(req: Request): string | null {
    const authHeader = req.headers.get("Authorization");
    if (authHeader) {
        const parts = authHeader.split(' ');
        if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
            return parts[1];
        }
    }

    const url = new URL(req.url);
    return (
        url.searchParams.get("api_key") ||
        url.searchParams.get("api-key") ||
        req.headers.get("api_key") ||
        req.headers.get("api-key") ||
        null
    );
}

async function checkApiKey(req: Request, env: Env): Promise<{valid: boolean, error?: string, maxPerDay?: number, maxCreditsPerDay?: number, isGrandfathered?: boolean, onetimeCreditsBalance?: number, onetimeCreditsExpiresAt?: string, cacheRefreshed?: boolean}> {
    const apiKey = getApiKeyFromRequest(req);
    if (!apiKey) return { valid: false };

    // Check cache first
    const cached = API_KEY_CACHE.get(apiKey);
    const now = Date.now();

    if (cached && (now - cached.cachedAt) < CACHE_TTL) {
        return {
            valid: cached.valid,
            error: cached.error,
            maxPerDay: cached.maxPerDay,
            maxCreditsPerDay: cached.maxCreditsPerDay,
            isGrandfathered: cached.isGrandfathered,
            onetimeCreditsBalance: cached.onetimeCreditsBalance,
            onetimeCreditsExpiresAt: cached.onetimeCreditsExpiresAt,
            cacheRefreshed: false
        };
    }

    // Cache miss — query Postgres via Hyperdrive
    let client: Client | null = null;

    try {
        client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
        await client.connect();

        const queryResult = await client.query(
            "SELECT max_per_day, max_credits_per_day, is_grandfathered, onetime_credits_balance, onetime_credits_expires_at FROM api_keys_view WHERE api_key = $1",
            [apiKey]
        );

        if (queryResult.rows.length === 0) {
            await client.end();
            const result = { valid: false, error: "API key not found" };
            API_KEY_CACHE.set(apiKey, { ...result, cachedAt: now });
            return result;
        }

        const row = queryResult.rows[0];

        // API key exists - consider it valid
        const result = {
            valid: true,
            maxPerDay: row.max_per_day as number,
            maxCreditsPerDay: row.max_credits_per_day as number,
            isGrandfathered: row.is_grandfathered as boolean,
            onetimeCreditsBalance: (row.onetime_credits_balance as number) ?? 0,
            onetimeCreditsExpiresAt: row.onetime_credits_expires_at ? String(row.onetime_credits_expires_at) : undefined,
            cacheRefreshed: true
        };

        await client.end();
        API_KEY_CACHE.set(apiKey, { ...result, cachedAt: now });
        return result;

    } catch (error) {
        // Fail-open: on DB errors, allow request with default rate limit
        console.error("Error checking API key via Hyperdrive:", error);
        if (client) {
            try { await client.end(); } catch { /* ignore */ }
        }
        return { valid: true, maxPerDay: 100000, maxCreditsPerDay: 100000, isGrandfathered: false, onetimeCreditsBalance: 0 };
    }
}

/**
 * Write back consumed one-time credits to the DB and sync with the DO.
 * Called in waitUntil() to not block requests.
 */
async function writebackOnetimeCredits(
    env: Env,
    apiKey: string,
    rateLimitKey: string,
    dailyLimit: number,
    onetimeBalance: number
): Promise<void> {
    try {
        // Get current consumed count from DO
        const id = env.RATE_LIMITER.idFromName(rateLimitKey);
        const limiter = env.RATE_LIMITER.get(id);

        const statusResult = await limiter.fetch("http://internal/status", {
            method: "POST",
            body: JSON.stringify({ dailyLimit, onetimeBalance })
        }).then(res => res.json() as Promise<{ onetime: { consumed: number } }>);

        const consumed = statusResult.onetime?.consumed ?? 0;
        if (consumed <= 0) return;

        // Write consumed credits to DB
        const client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
        await client.connect();

        await client.query(
            "UPDATE users SET onetime_credits_balance = GREATEST(0, onetime_credits_balance - $1) WHERE api_key = $2",
            [consumed, apiKey]
        );

        await client.end();

        // Tell DO to subtract what we wrote back
        await limiter.fetch("http://internal/sync", {
            method: "POST",
            body: JSON.stringify({ consumedWriteback: consumed })
        });

        console.log(`Writeback: ${consumed} onetime credits for key ${maskApiKey(apiKey)}`);
    } catch (error) {
        console.error("Onetime credits writeback error:", error);
    }
}

function getCorsHeaders(): Headers {
    const headers = new Headers();
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Accept, Accept-Language, Accept-Encoding, Authorization, Content-Type");
    headers.set("Access-Control-Expose-Headers", "Cache-Control, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Onetime-Remaining, X-RateLimit-Credits-Used, X-RateLimit-Credits-Required, X-RateLimit-Reset, Retry-After");
    return headers;
}

function addCorsHeaders(response: Response): Response {
    const newHeaders = new Headers(response.headers);
    const corsHeaders = getCorsHeaders();
    corsHeaders.forEach((value, key) => {
        newHeaders.set(key, value);
    });
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
    });
}

function getTargetApiUrl(url: URL, env: Env): string {
    const pathname = url.pathname;
    const normalizedPath = pathname.replace(/^\/*|\/*$/g, '').toLowerCase();

    // Route /text/* to TEXT_API_URL
    if (/^text\/?/.test(normalizedPath)) {
        return env.TEXT_API_URL;
    }

    // Check if this is an entity list endpoint (not a singleton)
    if (env.SEARCH_API_URL) {
        const segments = normalizedPath.split('/');
        const ENTITY_TYPES = ['works', 'authors', 'sources', 'institutions',
                              'topics', 'publishers', 'funders', 'concepts'];

        if (segments.length >= 1 && ENTITY_TYPES.includes(segments[0])) {
            const OPENALEX_ID_PATTERN = /^[A-Za-z]?\d+$/;
            const isSingleton = segments.length >= 2 && OPENALEX_ID_PATTERN.test(segments[1]);

            if (!isSingleton) {
                // Route to SEARCH_API_URL if request has search or search.* params
                if (url.searchParams.has('search')) {
                    return env.SEARCH_API_URL;
                }
                for (const key of url.searchParams.keys()) {
                    if (key.startsWith('search.')) {
                        return env.SEARCH_API_URL;
                    }
                }

                // Route to SEARCH_API_URL if filter contains search filters
                const filterParam = url.searchParams.get('filter');
                if (filterParam) {
                    const SEARCH_FILTERS = [
                        'abstract.search',
                        'default.search',
                        'display_name.search',
                        'fulltext.search',
                        'keyword.search',
                        'raw_affiliation_strings.search',
                        'raw_author_name.search',
                        'title.search',
                        'title_and_abstract.search'
                    ];
                    const hasSearchFilter = SEARCH_FILTERS.some(f => filterParam.includes(f));
                    if (hasSearchFilter) {
                        return env.SEARCH_API_URL;
                    }
                }
            }
        }
    }

    return env.OPENALEX_API_URL;
}

function getForwardPath(url: URL, targetApiUrl: string, env: Env): string {
    const pathname = url.pathname;
    if (/^\/text\/?/i.test(pathname) && targetApiUrl === env.TEXT_API_URL) {
        return pathname;
    }

    return pathname;
}

function checkProtectedParams(url: URL, hasValidApiKey: boolean): { valid: boolean; error?: string } {
    const filterParam = url.searchParams.get('filter');
    if (filterParam) {
        const filterPattern = /(?:from_|to_)?(?:updated|created)_date:[><]?\d{4}-\d{2}-\d{2}/;
        const matches = filterParam.match(filterPattern);
        if (matches && !hasValidApiKey) {
            return {
                valid: false,
                error: `You must include a valid API key to use "${matches[0]}" with filter`
            };
        }
    }

    const sortParam = url.searchParams.get('sort');
    if (sortParam) {
        const sortPattern = /(?:from_|to_)?(?:updated|created)_date(?::(?:asc|desc))?/;
        const matches = sortParam.match(sortPattern);
        if (matches && !hasValidApiKey) {
            return {
                valid: false,
                error: `You must include a valid API key to use "${matches[0]}" with sort`
            };
        }
    }

    return { valid: true };
}

function json(status: number, data: unknown): Response {
    const headers = new Headers({
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    });
    const corsHeaders = getCorsHeaders();
    corsHeaders.forEach((value, key) => {
        headers.set(key, value);
    });
    return new Response(JSON.stringify(data), { status, headers });
}

function getSecondsUntilMidnightUTC(): number {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    return Math.ceil((tomorrow.getTime() - now.getTime()) / 1000);
}

function getMidnightUTCISO(): string {
    const tomorrow = new Date();
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    return tomorrow.toISOString();
}

function maskApiKey(apiKey: string): string {
    if (apiKey.length <= 6) return '***';
    return apiKey.slice(0, 3) + '...' + apiKey.slice(-3);
}

async function handleRateLimitEndpoint(
    req: Request,
    env: Env,
    apiKey: string | null,
    hasValidApiKey: boolean,
    maxCreditsPerDay: number,
    isGrandfathered: boolean = false,
    onetimeCreditsBalance: number = 0,
    onetimeCreditsExpiresAt?: string
): Promise<Response> {
    // Require a valid API key
    if (!hasValidApiKey || !apiKey) {
        return json(401, {
            error: "Authentication required",
            message: "You must provide a valid API key to check rate limit status"
        });
    }

    // Query the rate limiter DO for current status (without incrementing)
    const rateLimitKey = `credits:${apiKey}`;
    const id = env.RATE_LIMITER.idFromName(rateLimitKey);
    const limiter = env.RATE_LIMITER.get(id);

    let statusResult: {
        daily: { used: number; remaining: number };
        onetime: { consumed: number; remaining: number; balance: number };
        used: number;
        remaining: number;
    };
    try {
        statusResult = await limiter.fetch("http://internal/status", {
            method: "POST",
            body: JSON.stringify({ dailyLimit: maxCreditsPerDay, onetimeBalance: onetimeCreditsBalance })
        }).then(res => res.json());
    } catch (error) {
        console.error("Rate limiter status error:", error);
        statusResult = {
            daily: { used: 0, remaining: maxCreditsPerDay },
            onetime: { consumed: 0, remaining: onetimeCreditsBalance, balance: onetimeCreditsBalance },
            used: 0,
            remaining: maxCreditsPerDay
        };
    }

    return json(200, {
        api_key: maskApiKey(apiKey),
        is_grandfathered: isGrandfathered,
        rate_limit: {
            credits_limit: maxCreditsPerDay,
            credits_used: statusResult.daily?.used ?? statusResult.used,
            credits_remaining: statusResult.daily?.remaining ?? statusResult.remaining,
            onetime_credits_balance: onetimeCreditsBalance,
            onetime_credits_remaining: statusResult.onetime?.remaining ?? 0,
            onetime_credits_expires_at: onetimeCreditsExpiresAt || null,
            resets_at: getMidnightUTCISO(),
            resets_in_seconds: getSecondsUntilMidnightUTC(),
            credit_costs: {
                singleton: 0,
                list: 1,
                search: 10,
                content: 100,
                vector: 10,
                text: 100
            }
        }
    });
}
