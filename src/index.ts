import { Client } from "pg";
import { RateLimiter } from "./rateLimiter";
import { logAnalytics, shouldSampleEsTook } from "./analytics";
import { classifyEndpoint, EndpointClassification } from "./endpointClassifier";
import { f1Reason, f1Message } from "./f1Validation";
import { isChangefilesBrowsePath, isChangefileDownloadPath } from "./changefilesPaths";

export interface Env {
    HYPERDRIVE: Hyperdrive;
    RATE_LIMITER: DurableObjectNamespace;
    ANALYTICS: AnalyticsEngineDataset;
    OPENALEX_API_URL: string;
    TEXT_API_URL: string;
    SEARCH_API_URL?: string;  // Optional - falls back to OPENALEX_API_URL if not set
    CONTENT_WORKER: Fetcher;  // Service binding to openalex-content-worker
    CV_PARSER?: Fetcher;      // Service binding to openalex-cv-parser
}

type ThrottleScope = 'user' | 'org';

interface ApiKeyAuth {
    valid: boolean;
    error?: string;
    maxPerDay?: number;
    maxCreditsPerDay?: number;
    isGrandfathered?: boolean;
    onetimeCreditsBalance?: number;
    onetimeCreditsExpiresAt?: string;
    plan?: string | null;
    rateThrottled?: boolean;
    throttleScope?: ThrottleScope | null;
    userId?: string | null;
    orgId?: string | null;
    cacheRefreshed?: boolean;
}

// In-memory cache for API key validation
const API_KEY_CACHE = new Map<string, ApiKeyAuth & { cachedAt: number }>();
const CACHE_TTL = 60000; // 60 seconds

// oxjob #166. Distinct from the 'throttled' plan value (max_per_day=0).
const THROTTLE_MESSAGE = "Your access is temporarily throttled while we investigate unsustainable usage patterns. Please contact support@openalex.org for details.";

// Conversion: 1 credit = $0.0001 (10,000 credits = $1)
const CREDIT_TO_USD = 0.0001;

function creditsToUsd(credits: number): number {
    return Math.round(credits * CREDIT_TO_USD * 10000) / 10000; // 4 decimal places
}

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

        // Route /cv-parse/* to CV parser worker (before API key validation —
        // CV parse uses user JWT auth, not OpenAlex API keys)
        if (env.CV_PARSER && /^\/cv-parse(\/|$)/i.test(url.pathname)) {
            const cvPath = url.pathname.replace(/^\/cv-parse/, '') || '/';
            const cvUrl = new URL(req.url);
            cvUrl.pathname = cvPath;
            const cvResponse = await env.CV_PARSER.fetch(new Request(cvUrl, req));
            return addCorsHeaders(new Response(cvResponse.body, {
                status: cvResponse.status,
                headers: cvResponse.headers,
            }));
        }

        const apiKey = getApiKeyFromRequest(req);
        let hasValidApiKey = false;

        // Changefiles browsing: tolerate placeholder keys (e.g., "YOUR_API_KEY")
        // without a 401 so users can browse available files without a real key.
        // Path matching lives in changefilesPaths.ts (shared with the classifier
        // and download gate so they can't drift — zd#8865).
        const isChangefilesBrowse = isChangefilesBrowsePath(url.pathname);
        // TODO Feb 13, 2026: Change these to 100 to require API key for normal usage.
        // 2026-01-26: Reduced from 100K to 10K during API slowdown incident to shift capacity to API key holders.
        // With list=1 credit, users can make 10K list requests/day without an API key.
        let maxPerDay = 10000;  // Default daily rate limit for unauthenticated users
        let maxCreditsPerDay = 10000;  // Default credits for unauthenticated users (1:1)
        let isGrandfathered = false;  // Unauthenticated users are not grandfathered

        let onetimeCreditsBalance = 0;
        let onetimeCreditsExpiresAt: string | undefined;
        let userPlan: string | null = null;

        if (apiKey) {
            const authResult = await checkApiKey(req, env);
            if (!authResult.valid) {
                // Changefiles browse paths (/changefiles, /changefiles/{date})
                // tolerate placeholder/invalid keys (e.g. "YOUR_API_KEY") so anyone
                // can list available files — fall through and treat the request as
                // anonymous. For every other path, an invalid key is a hard 401.
                if (!isChangefilesBrowse) {
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
            } else {
                // Valid key — honor the account's limits, plan, and balance on
                // EVERY path, including changefiles browse. Previously browse paths
                // skipped this block entirely (`apiKey && !isChangefilesBrowse`),
                // silently dropping authenticated users to the anonymous limit on
                // /changefiles and /changefiles/{date} (zd#8865).
                hasValidApiKey = true;
                maxPerDay = authResult.maxPerDay ?? 100000;
                maxCreditsPerDay = authResult.maxCreditsPerDay ?? maxPerDay;
                isGrandfathered = authResult.isGrandfathered || false;
                onetimeCreditsBalance = authResult.onetimeCreditsBalance ?? 0;
                onetimeCreditsExpiresAt = authResult.onetimeCreditsExpiresAt;
                userPlan = authResult.plan ?? null;

                // Throttled accounts get a 1 req/sec gate via a separate DO namespace
                // ('throttle:user|org:{id}'), so org throttles share one bucket across
                // all org keys.
                if (authResult.rateThrottled) {
                    const throttleId = authResult.throttleScope === 'org'
                        ? `throttle:org:${authResult.orgId}`
                        : `throttle:user:${authResult.userId}`;
                    try {
                        const throttleLimiter = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(throttleId));
                        const throttleCheck = await throttleLimiter.fetch("http://internal/check-throttle", {
                            method: "POST",
                            body: JSON.stringify({})
                        }).then(res => res.json() as Promise<{ success: boolean; retryAfter?: number }>);

                        if (!throttleCheck.success) {
                            const retryAfter = Math.ceil(throttleCheck.retryAfter || 1);
                            const errorResponse = new Response(JSON.stringify({
                                error: "Rate limit exceeded",
                                message: THROTTLE_MESSAGE,
                                retryAfter
                            }), {
                                status: 429,
                                headers: {
                                    "Content-Type": "application/json",
                                    "Retry-After": retryAfter.toString(),
                                    ...Object.fromEntries(getCorsHeaders())
                                }
                            });

                            logAnalytics({
                                ctx, env, apiKey, req, url,
                                scope: 'throttle',
                                responseTime: Date.now() - startTime,
                                statusCode: 429,
                                rateLimit: 1,
                                rateLimitRemaining: 0
                            });

                            return errorResponse;
                        }
                    } catch (error) {
                        // Fail-open: if the throttle DO call errors, let the request through
                        // and rely on the credits bucket. Avoids breaking traffic on infra hiccups.
                        console.error("Rate-throttle DO error:", error);
                    }
                }

                // Trigger writeback of consumed one-time credits on cache refresh (non-blocking)
                if (authResult.cacheRefreshed && onetimeCreditsBalance > 0) {
                    const wbRateLimitKey = `credits:${apiKey}`;
                    ctx.waitUntil(
                        writebackOnetimeCredits(env, apiKey, wbRateLimitKey, maxCreditsPerDay, onetimeCreditsBalance)
                    );
                }
            }
        }

        const protectedParamCheck = checkProtectedParams(url, hasValidApiKey, userPlan);
        if (!protectedParamCheck.valid) {
            const errorResponse = json(429, {
                error: "Plan upgrade required",
                message: protectedParamCheck.error
            });

            // Log 429 plan-restriction error
            logAnalytics({
                ctx,
                env,
                apiKey,
                req,
                url,
                scope: 'main',
                responseTime: Date.now() - startTime,
                statusCode: 429,
                rateLimit: 0,
                rateLimitRemaining: 0
            });

            return errorResponse;
        }

        // Changefiles downloads require a valid API key on a Premium, Institutional, or Partner plan.
        // Gated here (before the rate limiter) so rejected requests don't consume credits.
        if (isChangefileDownloadPath(url.pathname)) {
            if (!hasValidApiKey) {
                return json(401, {
                    error: "API key required",
                    message: "Changefile downloads require an API key. Get one at https://openalex.org/pricing"
                });
            }
            if (!userPlan || !ENTERPRISE_PLANS.has(userPlan)) {
                return json(403, {
                    error: "Plan upgrade required",
                    message: "Changefile downloads require a Premium, Institutional, or Partner plan. See https://openalex.org/pricing for details."
                });
            }
        }

        // Snapshot credentials vending requires a valid API key on a Premium, Institutional, or Partner plan.
        // Gated here (before the rate limiter) so rejected requests don't consume credits.
        if (/^\/snapshots\/credentials\/?$/i.test(url.pathname)) {
            if (!hasValidApiKey) {
                return json(401, {
                    error: "API key required",
                    message: "Snapshot credentials require an API key. Get one at https://openalex.org/pricing"
                });
            }
            if (!userPlan || !ENTERPRISE_PLANS.has(userPlan)) {
                return json(403, {
                    error: "Plan upgrade required",
                    message: "Snapshot access requires a Premium, Institutional, or Partner plan. See https://openalex.org/pricing for details."
                });
            }
        }

        // Handle /rate-limit endpoint
        const normalizedPath = url.pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
        if (normalizedPath === 'rate-limit') {
            // Support ?fresh=1 to bypass cache (used after purchase redirect)
            if (apiKey && url.searchParams.get('fresh') === '1') {
                API_KEY_CACHE.delete(apiKey);
                const freshAuth = await checkApiKey(req, env);
                if (freshAuth.valid) {
                    onetimeCreditsBalance = freshAuth.onetimeCreditsBalance ?? 0;
                    onetimeCreditsExpiresAt = freshAuth.onetimeCreditsExpiresAt;
                }
            }
            return await handleRateLimitEndpoint(req, env, apiKey, hasValidApiKey, maxCreditsPerDay, isGrandfathered, onetimeCreditsBalance, onetimeCreditsExpiresAt);
        }

        // Classify endpoint and determine credit cost
        const classification = classifyEndpoint(url.pathname, url.searchParams);
        // Grandfathered users get search at 1 credit instead of 10
        const creditCost = (isGrandfathered && classification.type === 'search')
            ? 1
            : classification.creditCost;

        // Use unified credits-based rate limiting
        const scope = "credits";
        const identifier = apiKey || req.headers.get("CF-Connecting-IP") || "anon";
        const rateLimitKey = `${scope}:${identifier}`;
        const limit = maxCreditsPerDay;

        // Check rate limit using Durable Object
        const id = env.RATE_LIMITER.idFromName(rateLimitKey);
        const limiter = env.RATE_LIMITER.get(id);

        // Temporary: enforce 1 req/s per user for semantic search
        if (classification.type === 'semantic') {
            try {
                const semanticCheck = await limiter.fetch("http://internal/check-semantic", {
                    method: "POST",
                    body: JSON.stringify({ dailyLimit: limit })
                }).then(res => res.json() as Promise<{ success: boolean; retryAfter?: number }>);

                if (!semanticCheck.success) {
                    const retryAfter = Math.ceil(semanticCheck.retryAfter || 1);
                    const errorResponse = new Response(JSON.stringify({
                        error: "Rate limit exceeded",
                        message: `Semantic search is limited to 1 request per second. Please wait and try again.`,
                        retryAfter
                    }), {
                        status: 429,
                        headers: {
                            "Content-Type": "application/json",
                            "Retry-After": retryAfter.toString(),
                            ...Object.fromEntries(getCorsHeaders())
                        }
                    });

                    logAnalytics({
                        ctx, env, apiKey, req, url, scope,
                        responseTime: Date.now() - startTime,
                        statusCode: 429,
                        rateLimit: limit,
                        rateLimitRemaining: 0,
                        endpointType: classification.type,
                        creditCost
                    });

                    return errorResponse;
                }
            } catch (error) {
                // Fail-open: if DO call fails, allow the request through
                console.error("Semantic rate limit check error:", error);
            }
        }

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
            const costUsd = creditsToUsd(creditCost);
            const dailyRemainingUsd = creditsToUsd(rateLimitResult.remaining ?? 0);
            const prepaidRemainingUsd = creditsToUsd(rateLimitResult.onetimeRemaining ?? 0);

            let message: string;
            if (isPerSecond) {
                message = `Rate limit exceeded: 100 requests per second. Please slow down.`;
            } else if (onetimeCreditsBalance > 0) {
                message = `Insufficient budget. This request costs $${costUsd} but you have $${dailyRemainingUsd} daily budget and $${prepaidRemainingUsd} prepaid balance remaining. Daily budget resets at midnight UTC. Add funds at https://openalex.org/pricing`;
            } else {
                message = `Insufficient budget. This request costs $${costUsd} but you only have $${dailyRemainingUsd} remaining. Resets at midnight UTC. Need more? Add funds at https://openalex.org/pricing`;
            }

            const errorResponse = new Response(JSON.stringify({
                error: "Rate limit exceeded",
                message,
                retryAfter: rateLimitResult.retryAfter,
                // New USD fields
                costUsd,
                dailyRemainingUsd,
                prepaidRemainingUsd,
                // Legacy credit fields (kept for backward compat during transition)
                creditsRequired: creditCost,
                creditsRemaining: rateLimitResult.remaining,
                onetimeCreditsRemaining: rateLimitResult.onetimeRemaining ?? 0
            }), {
                status: 429,
                headers: {
                    "Content-Type": "application/json",
                    "Retry-After": Math.ceil(rateLimitResult.retryAfter || 1).toString(),
                    // New USD headers
                    "X-RateLimit-Limit-USD": creditsToUsd(limit).toString(),
                    "X-RateLimit-Remaining-USD": dailyRemainingUsd.toString(),
                    "X-RateLimit-Prepaid-Remaining-USD": prepaidRemainingUsd.toString(),
                    "X-RateLimit-Cost-Required-USD": costUsd.toString(),
                    // Legacy headers (kept for backward compat during transition)
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
            // New USD headers
            newHeaders.set("X-RateLimit-Limit-USD", creditsToUsd(limit).toString());
            newHeaders.set("X-RateLimit-Remaining-USD", creditsToUsd(adjustedRemaining).toString());
            newHeaders.set("X-RateLimit-Prepaid-Remaining-USD", creditsToUsd(adjustedOnetimeRemaining).toString());
            newHeaders.set("X-RateLimit-Cost-USD", creditsToUsd(actualCost).toString());
            // Legacy headers (kept for backward compat during transition)
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

        // F1 edge fast-fail (oxjob #194). Reject two high-volume client-bug
        // shapes that are guaranteed `APIQueryParamsError` 400s at the
        // elastic-api origin — `limit=` typo and raw-comma filter values — so
        // they return the same 400 ~175ms sooner without burning a gunicorn
        // worker. See src/f1Validation.ts for the rules + the SUBSET INVARIANT
        // (edge may only reject what origin would also reject). The 400 is
        // self-identifying (error_source + x-openalex-edge-reject header) so a
        // debugger sees it never reached Heroku. POST skipped (filter may be in
        // body, not the query string), matching the request-line guard below.
        if (req.method !== "POST") {
            const reason = f1Reason(openalexUrl);
            if (reason) {
                return new Response(JSON.stringify({
                    error: "Invalid request rejected at the API edge",
                    error_source: "openalex-api-proxy",
                    message: f1Message(reason)
                }), {
                    status: 400,
                    headers: {
                        "Content-Type": "application/json",
                        "x-openalex-edge-reject": `f1:${reason}`,
                        ...Object.fromEntries(getCorsHeaders())
                    }
                });
            }
        }

        // Guard the HTTP request-line length. The origin runs gunicorn with
        // `--limit-request-line 8190` (its max finite value — raised from the
        // 4094 default in oxjob #373 to give OQL/long `search=` queries more
        // headroom). A longer request line is rejected with a raw HTML "400 Bad
        // Request: Request Line is too large" (and, in a transition band,
        // surfaces here as a confusing 500). Long Boolean `search=` queries and
        // long OQL `?oql=` queries hit this. Return one clear, actionable JSON
        // error instead of the raw HTML / 500. (oxjob #191.3, #373)
        // POST requests carry the query in the body, not the request line — skip
        // (OQL callers over the cap should re-submit via `POST /` with {oql}).
        if (req.method !== "POST") {
            const MAX_REQUEST_LINE_BYTES = 8190; // gunicorn --limit-request-line (max finite)
            const requestLine = `${req.method} ${openalexUrl.pathname}${openalexUrl.search} HTTP/1.1`;
            const requestLineBytes = new TextEncoder().encode(requestLine).length;
            if (requestLineBytes > MAX_REQUEST_LINE_BYTES) {
                // OQL-specific diagnostic when the over-limit query is `?oql=`:
                // the OQL execute route accepts the same query via a POST body,
                // which has no request-line cap.
                const isOql = openalexUrl.searchParams.has("oql");
                const message = isOql
                    ? `Your OQL query URL is ${requestLineBytes} bytes, over the ${MAX_REQUEST_LINE_BYTES}-byte limit for URLs (roughly 8 KB). This query is too long to share as a URL — submit it via POST to / with a JSON body {"oql": "..."}, which has no length limit.`
                    : `Your request URL is ${requestLineBytes} bytes, over the ${MAX_REQUEST_LINE_BYTES}-byte limit (roughly 8 KB, mostly the 'search' value). Split a large Boolean query into smaller chunks, request each separately, and combine the returned IDs client-side. See https://docs.openalex.org/guides/searching#large-boolean-queries`;
                const errorResponse = new Response(JSON.stringify({
                    error: isOql ? "OQL query too long for URL" : "Request URL too long",
                    message
                }), {
                    status: 400,
                    headers: {
                        "Content-Type": "application/json",
                        ...Object.fromEntries(getCorsHeaders())
                    }
                });
                return errorResponse;
            }
        }

        // For POST requests, we need to clone the request to preserve the body
        const proxyHeaders = new Headers({
            "User-Agent": "OpenAlex-Proxy/1.0",
            "Accept": req.headers.get("Accept") || "application/json",
            "Accept-Encoding": req.headers.get("Accept-Encoding") || "",
            "X-Cost-USD": creditsToUsd(creditCost).toString()
        });

        // Only add Content-Type for POST requests
        if (req.method === "POST") {
            proxyHeaders.set("Content-Type", req.headers.get("Content-Type") || "application/json");
        }

        // Forward Authorization so elastic-api can relay it to users-api for
        // private-label resolution (oxjob #228 QA-040). Proxy has already
        // validated the api_key above; users-api re-validates by lookup.
        const incomingAuth = req.headers.get("Authorization");
        if (incomingAuth) {
            proxyHeaders.set("Authorization", incomingAuth);
        }

        const proxyReq = new Request(openalexUrl.toString(), {
            method: req.method,
            headers: proxyHeaders,
            body: req.method === "POST" ? await req.clone().arrayBuffer() : undefined
        });

        // Edge-cache the changefiles listing for 1h. /changefiles and
        // /changefiles/{date} are 0-credit discovery endpoints whose contents
        // change ~daily; caching at the edge absorbs any hammering before it
        // reaches the origin — this, not rate limiting, is what protects them now
        // that they're unlimited (zd#8865). cf.cacheTtl pins a 1h edge TTL
        // regardless of the origin's own Cache-Control (which is 4h); cacheEverything
        // caches the JSON body. The cache is keyed on the full request URL, so each
        // api_key gets its own entry — important because the listing body embeds the
        // caller's api_key in the returned download URLs, so entries must NOT be
        // shared across keys. Downloads (/changefiles/{date}/{file}) are not browse
        // paths and are never cached here.
        const isChangefilesListing = req.method === "GET" && isChangefilesBrowse;
        const response = await fetch(
            proxyReq,
            isChangefilesListing ? { cf: { cacheTtl: 3600, cacheEverything: true } } : {}
        );

        // Sampled clone for analytics body-read (oxjob #194). Must be taken
        // BEFORE response.body is consumed by the streamed `new Response(...)`
        // below — once a body stream is used, it can't be cloned. The clone
        // tees the body into two independent streams; user stream is unaffected.
        const sampledResponseForAnalytics = shouldSampleEsTook() ? response.clone() : null;

        // Return response with rate limit headers
        const newHeaders = new Headers(response.headers);
        // New USD headers
        newHeaders.set("X-RateLimit-Limit-USD", creditsToUsd(limit).toString());
        newHeaders.set("X-RateLimit-Remaining-USD", creditsToUsd(rateLimitResult.remaining ?? 0).toString());
        newHeaders.set("X-RateLimit-Prepaid-Remaining-USD", creditsToUsd(rateLimitResult.onetimeRemaining ?? 0).toString());
        newHeaders.set("X-RateLimit-Cost-USD", creditsToUsd(creditCost).toString());
        // Legacy headers (kept for backward compat during transition)
        newHeaders.set("X-RateLimit-Limit", limit.toString());
        newHeaders.set("X-RateLimit-Remaining", (rateLimitResult.remaining ?? 0).toString());
        newHeaders.set("X-RateLimit-Onetime-Remaining", (rateLimitResult.onetimeRemaining ?? 0).toString());
        newHeaders.set("X-RateLimit-Credits-Used", creditCost.toString());
        newHeaders.set("X-RateLimit-Reset", getSecondsUntilMidnightUTC().toString());

        // Surface the 1h listing TTL to clients/downstream too, overriding the
        // origin's 4h Cache-Control (zd#8865).
        if (isChangefilesListing) {
            newHeaders.set("Cache-Control", "public, max-age=3600");
        }

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
            creditCost,
            responseForEsTook: sampledResponseForAnalytics
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

async function checkApiKey(req: Request, env: Env): Promise<ApiKeyAuth> {
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
            plan: cached.plan,
            rateThrottled: cached.rateThrottled,
            throttleScope: cached.throttleScope,
            userId: cached.userId,
            orgId: cached.orgId,
            cacheRefreshed: false
        };
    }

    // Cache miss — query Postgres via Hyperdrive
    let client: Client | null = null;

    try {
        client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
        await client.connect();

        const queryResult = await client.query(
            "SELECT max_per_day, max_credits_per_day, is_grandfathered, onetime_credits_balance, onetime_credits_expires_at, plan, rate_throttled, throttle_scope, user_id, org_id FROM api_keys_view WHERE api_key = $1",
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
        const result: ApiKeyAuth = {
            valid: true,
            maxPerDay: row.max_per_day as number,
            maxCreditsPerDay: row.max_credits_per_day as number,
            isGrandfathered: row.is_grandfathered as boolean,
            onetimeCreditsBalance: (row.onetime_credits_balance as number) ?? 0,
            onetimeCreditsExpiresAt: row.onetime_credits_expires_at ? String(row.onetime_credits_expires_at) : undefined,
            plan: (row.plan as string) ?? null,
            rateThrottled: Boolean(row.rate_throttled),
            throttleScope: (row.throttle_scope as ThrottleScope | null) ?? null,
            userId: (row.user_id as string) ?? null,
            orgId: (row.org_id as string) ?? null,
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
        return { valid: true, maxPerDay: 100000, maxCreditsPerDay: 100000, isGrandfathered: false, onetimeCreditsBalance: 0, plan: null, rateThrottled: false, throttleScope: null, userId: null, orgId: null };
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
        // Atomically claim consumed credits from the DO.
        // This reads the consumed count AND resets it to 0 in one serialized call,
        // preventing concurrent writebacks from reading the same value.
        const id = env.RATE_LIMITER.idFromName(rateLimitKey);
        const limiter = env.RATE_LIMITER.get(id);

        const claimResult = await limiter.fetch("http://internal/begin-writeback", {
            method: "POST",
            body: JSON.stringify({ dailyLimit, onetimeBalance })
        }).then(res => res.json() as Promise<{ consumed: number }>);

        const consumed = claimResult.consumed ?? 0;
        if (consumed <= 0) return;

        // Write consumed credits to DB
        const client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
        await client.connect();

        try {
            await client.query(
                "UPDATE users SET onetime_credits_balance = GREATEST(0, onetime_credits_balance - $1) WHERE api_key = $2",
                [consumed, apiKey]
            );
        } catch (dbError) {
            // DB write failed — restore consumed credits to the DO so they aren't lost.
            // /begin-writeback already reset consumed to 0, so we must re-add.
            console.error("DB writeback failed, restoring credits to DO:", dbError);
            try {
                await limiter.fetch("http://internal/restore-consumed", {
                    method: "POST",
                    body: JSON.stringify({ dailyLimit, consumedWriteback: consumed, onetimeBalance })
                });
            } catch { /* best effort */ }
            throw dbError;
        }

        await client.end();

        // Update the in-memory cache so subsequent requests (within the 60s TTL)
        // see the correct post-writeback balance. Without this, the stale cache
        // feeds the old (higher) balance to the DO, allowing overspend.
        const cached = API_KEY_CACHE.get(apiKey);
        if (cached && cached.onetimeCreditsBalance !== undefined) {
            cached.onetimeCreditsBalance = Math.max(0, cached.onetimeCreditsBalance - consumed);
        }

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
    headers.set("Access-Control-Expose-Headers", "Cache-Control, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Onetime-Remaining, X-RateLimit-Credits-Used, X-RateLimit-Credits-Required, X-RateLimit-Reset, X-RateLimit-Limit-USD, X-RateLimit-Remaining-USD, X-RateLimit-Prepaid-Remaining-USD, X-RateLimit-Cost-USD, X-RateLimit-Cost-Required-USD, Retry-After");
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
                const filterParams = url.searchParams.getAll('filter');
                if (filterParams.length > 0) {
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
                    const hasSearchFilter = filterParams.some(fp =>
                        SEARCH_FILTERS.some(f => fp.includes(f))
                    );
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

// Enterprise-tier plans: gated access to date filters, changefile downloads, etc.
const ENTERPRISE_PLANS = new Set([
    'premium-1M', 'premium-2M', 'premium-5M', 'premium-10M',
    'institutional', 'institutional-1M', 'institutional-2M',
    'partner',
]);

function checkProtectedParams(url: URL, hasValidApiKey: boolean, plan: string | null): { valid: boolean; error?: string } {
    const hasPlanAccess = plan !== null && ENTERPRISE_PLANS.has(plan);

    // Use getAll() to check ALL values — duplicate params (e.g., ?filter=safe&filter=date_filter)
    // could bypass the check if we only inspect the first value.
    const filterParams = url.searchParams.getAll('filter');
    for (const filterParam of filterParams) {
        const filterPattern = /(?:from_|to_)?(?:updated|created)_date:[><]?\d{4}-\d{2}-\d{2}/;
        const matches = filterParam.match(filterPattern);
        if (matches && !hasPlanAccess) {
            return {
                valid: false,
                error: `The "${matches[0]}" filter requires a Premium, Institutional, or Partner plan. See https://openalex.org/pricing for details.`
            };
        }
    }

    const sortParams = url.searchParams.getAll('sort');
    for (const sortParam of sortParams) {
        const sortPattern = /(?:from_|to_)?(?:updated|created)_date(?::(?:asc|desc))?/;
        const matches = sortParam.match(sortPattern);
        if (matches && !hasPlanAccess) {
            return {
                valid: false,
                error: `Sorting by "${matches[0]}" requires a Premium, Institutional, or Partner plan. See https://openalex.org/pricing for details.`
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

    const dailyUsed = statusResult.daily?.used ?? statusResult.used;
    const dailyRemaining = statusResult.daily?.remaining ?? statusResult.remaining;
    const onetimeRemaining = statusResult.onetime?.remaining ?? 0;
    const searchCreditCost = isGrandfathered ? 1 : 10;

    return json(200, {
        api_key: maskApiKey(apiKey),
        is_grandfathered: isGrandfathered,
        rate_limit: {
            // New USD fields
            daily_budget_usd: creditsToUsd(maxCreditsPerDay),
            daily_used_usd: creditsToUsd(dailyUsed),
            daily_remaining_usd: creditsToUsd(dailyRemaining),
            prepaid_balance_usd: creditsToUsd(onetimeCreditsBalance),
            prepaid_remaining_usd: creditsToUsd(onetimeRemaining),
            prepaid_expires_at: onetimeCreditsExpiresAt || null,
            resets_at: getMidnightUTCISO(),
            resets_in_seconds: getSecondsUntilMidnightUTC(),
            endpoint_costs_usd: {
                singleton: 0,
                list: creditsToUsd(1),
                search: creditsToUsd(searchCreditCost),
                content: creditsToUsd(100),
                semantic: creditsToUsd(10),
                text: creditsToUsd(100)
            },
            // Legacy credit fields (kept for backward compat during transition)
            credits_limit: maxCreditsPerDay,
            credits_used: dailyUsed,
            credits_remaining: dailyRemaining,
            onetime_credits_balance: onetimeCreditsBalance,
            onetime_credits_remaining: onetimeRemaining,
            onetime_credits_expires_at: onetimeCreditsExpiresAt || null,
            credit_costs: {
                singleton: 0,
                list: 1,
                search: searchCreditCost,
                content: 100,
                semantic: 10,
                text: 100
            }
        }
    });
}
