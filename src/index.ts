import { RateLimiter } from "./rateLimiter";
import { logAnalytics } from "./analytics";

export interface Env {
    openalex_db: D1Database;
    RATE_LIMITER: DurableObjectNamespace;
    ANALYTICS: AnalyticsEngineDataset;
    OPENALEX_API_URL: string;
    EXPORTER_API_URL: string;
    TEXT_API_URL: string;
    USERS_API_URL: string;
}

// In-memory cache for API key validation
const API_KEY_CACHE = new Map<string, {
    valid: boolean;
    maxPerSecond?: number;
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
        let maxPerSecond = 5;  // Default rate limit for unauthenticated users

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
                    scope: 'main',
                    responseTime: Date.now() - startTime,
                    statusCode: 401,
                    rateLimit: 0,
                    rateLimitRemaining: 0
                });

                return errorResponse;
            }
            hasValidApiKey = true;
            maxPerSecond = authResult.maxPerSecond || 50;
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

        // Determine rate limits based on path
        const normalizedPath = url.pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
        const isTextPath = /^text\/?/.test(normalizedPath);
        const isUsersPath = /^users\/?/.test(normalizedPath);
        const isExportPath = /^export\/?/.test(normalizedPath) ||
                            /^(?:works\/+)?[wW]\d+\.bib$/.test(normalizedPath) ||
                            (/^works\/?/.test(normalizedPath) &&
                             url.searchParams.get('format') &&
                             ['csv', 'ris', 'wos-plaintext', 'zip'].includes(url.searchParams.get('format')?.trim().toLowerCase() || ''));

        let limit: number;
        if (isTextPath) {
            limit = 5;
        } else if (isUsersPath || isExportPath) {
            limit = 10;
        } else {
            limit = maxPerSecond;
        }

        // Create rate limit key
        const scope = isTextPath ? "text" : isUsersPath ? "users" : isExportPath ? "export" : "main";
        const identifier = apiKey || req.headers.get("CF-Connecting-IP") || "anon";
        const rateLimitKey = `${scope}:${identifier}`;

        // Check rate limit using Durable Object
        const id = env.RATE_LIMITER.idFromName(rateLimitKey);
        const limiter = env.RATE_LIMITER.get(id);

        // Apply burst capacity only for anonymous users
        const burstCapacity = apiKey ? limit : limit * 2;

        const rateLimitResult = await limiter.fetch("http://internal/check", {
            method: "POST",
            body: JSON.stringify({
                limit,
                burstCapacity
            })
        }).then(res => res.json<{
            success: boolean;
            retryAfter?: number;
            tokensRemaining?: number;
        }>());

        // Handle rate limit exceeded
        if (!rateLimitResult.success) {
            const errorResponse = new Response(JSON.stringify({
                error: "Rate limit exceeded",
                message: `You have exceeded the rate limit of ${limit} requests per second. Please try again later.`,
                retryAfter: rateLimitResult.retryAfter
            }), {
                status: 429,
                headers: {
                    "Content-Type": "application/json",
                    "Retry-After": Math.ceil(rateLimitResult.retryAfter || 1).toString(),
                    "RateLimit-Limit": limit.toString(),
                    "RateLimit-Remaining": "0",
                    "RateLimit-Reset": "1",
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
                rateLimitRemaining: 0
            });

            return errorResponse;
        }

        const targetApiUrl = getTargetApiUrl(url, env);

        const forwardPath = getForwardPath(url, targetApiUrl, env);

        const openalexUrl = new URL(targetApiUrl + forwardPath);

        url.searchParams.forEach((value, key) => {
            openalexUrl.searchParams.set(key, value);
        });

        const proxyReq = new Request(openalexUrl.toString(), {
            method: req.method,
            headers: {
                "User-Agent": "OpenAlex-Proxy/1.0",
                "Accept": req.headers.get("Accept") || "application/json"
            }
        });

        const response = await fetch(proxyReq);

        // Return response with rate limit headers
        const newHeaders = new Headers(response.headers);
        newHeaders.set("RateLimit-Limit", limit.toString());
        newHeaders.set("RateLimit-Remaining", Math.floor(rateLimitResult.tokensRemaining || 0).toString());
        newHeaders.set("RateLimit-Reset", "1");

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
            rateLimitRemaining: Math.floor(rateLimitResult.tokensRemaining || 0)
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

async function checkApiKey(req: Request, env: Env): Promise<{valid: boolean, error?: string, maxPerSecond?: number}> {
    const apiKey = getApiKeyFromRequest(req);
    if (!apiKey) return { valid: false };

    // Check cache first
    const cached = API_KEY_CACHE.get(apiKey);
    const now = Date.now();

    if (cached && (now - cached.cachedAt) < CACHE_TTL) {
        return {
            valid: cached.valid,
            error: cached.error,
            maxPerSecond: cached.maxPerSecond
        };
    }

    // Cache miss - query D1
    try {
        const keyData = await env.openalex_db
            .prepare("SELECT expires_at, max_per_second FROM api_keys WHERE api_key = ?")
            .bind(apiKey)
            .first();

        if (!keyData) {
            const result = { valid: false, error: "API key not found" };
            API_KEY_CACHE.set(apiKey, { ...result, cachedAt: now });
            return result;
        }

        // API key exists - consider it valid (expiration checking removed)
        const result = {
            valid: true,
            maxPerSecond: keyData.max_per_second as number
        };
        API_KEY_CACHE.set(apiKey, { ...result, cachedAt: now });
        return result;

    } catch (error) {
        console.error("Error checking API key:", error);
        return { valid: false, error: "Database error" };
    }
}

function getCorsHeaders(): Headers {
    const headers = new Headers();
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Accept, Accept-Language, Accept-Encoding, Authorization, Content-Type");
    headers.set("Access-Control-Expose-Headers", "Cache-Control, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, Retry-After");
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
    const normalizedPath = pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
    const hasQueryParams = url.search.length > 0;

    if (/^text\/?/.test(normalizedPath)) {
        return env.TEXT_API_URL;
    }
    if (/^users\/?/.test(normalizedPath)) {
        return env.USERS_API_URL;
    }
    if (/^(?:works\/+)?[wW]\d+\.bib$/.test(normalizedPath) && !hasQueryParams) {
        return env.EXPORTER_API_URL;
    }
    if (/^works\/?/.test(normalizedPath)) {
        const format = url.searchParams.get('format');
        const groupBy = url.searchParams.get('group_by');
        const groupBys = url.searchParams.get('group_bys');
        if (format &&
            ['csv', 'ris', 'wos-plaintext', 'zip'].includes(format.trim().toLowerCase()) &&
            !groupBy && !groupBys) {
            return env.EXPORTER_API_URL;
        }
    }
    if (/^export\/?/.test(normalizedPath)) {
        return env.EXPORTER_API_URL;
    }
    return env.OPENALEX_API_URL;
}

function getForwardPath(url: URL, targetApiUrl: string, env: Env): string {
    const pathname = url.pathname;

    if (/^\/users\/?/i.test(pathname) && targetApiUrl === env.USERS_API_URL) {
        const forwardPath = pathname.replace(/^\/users\/?/, '/');
        return forwardPath === '' ? '/' : forwardPath;
    }

    if (/^\/text\/?/i.test(pathname) && targetApiUrl === env.TEXT_API_URL) {
        const forwardPath = pathname.replace(/^\/text\/?/, '/');
        return forwardPath === '' ? '/' : forwardPath;
    }

    if (/^\/export\/?/i.test(pathname) && targetApiUrl === env.EXPORTER_API_URL) {
        const forwardPath = pathname.replace(/^\/export\/?/, '/');
        return forwardPath === '' ? '/' : forwardPath;
    }

    return pathname;
}

function checkProtectedParams(url: URL, hasValidApiKey: boolean): { valid: boolean; error?: string } {
    const filterParam = url.searchParams.get('filter');
    if (filterParam) {
        const filterPattern = /(?:from|to)_(?:updated|created)_date:[><]?\d{4}-\d{2}-\d{2}/;
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
        const sortPattern = /(?:from|to)_(?:updated|created)_date(?::(?:asc|desc))?/;
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
