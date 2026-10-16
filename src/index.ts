import { isCacheableCountProbe } from './countProbe';
import { authorizationToForward } from './forwardAuth';
import { isAuthorFixesPath, authorFixesRequest } from './authorFixes';
import { isCollectionsPath, collectionsRequest, USERS_API_URL } from './collections';
import { Client } from "pg";
import { RateLimiter } from "./rateLimiter";
import { actualCreditCost, creditsRemainingForOrigin, settleCredits, ORIGIN_COST_HEADER, CREDITS_REMAINING_HEADER, GRANDFATHERED_HEADER, WEBSITE_HEADER } from "./creditReconcile";
import { logAnalytics, shouldSampleEsTook } from "./analytics";
import { classifyEndpoint, countBooleanOperators, countWideOrTerms, WIDE_OR_MAX_TERMS, EndpointClassification, isRerank, bodyAsksRerank, rerankCredits, RERANK_CREDITS, queryTextAllowed } from "./endpointClassifier";
import { f1Reason, f1Message } from "./f1Validation";
import { checkSearchVolume, searchVolumeMessage } from "./searchVolumeGate";
import { isKeylessCursorPage, KEYLESS_CURSOR_ERROR } from "./cursorGate";
import { syncFieldInParams, requestOqlText, mightNameSyncField, readXQuery, syncFieldInXQuery, oqlSyncMessage } from "./syncGate";
import { semanticSearchKey } from "./semanticGate";
import { isChangefilesBrowsePath, isChangefileDownloadPath } from "./changefilesPaths";
import { mintUiToken, networkOf, verifyUiToken, verifyTurnstile } from "./uiToken";
import { isVerifiedAssistant, VERIFIED_ASSISTANT_HEADER, VERIFIED_ASSISTANT_CREDITS_PER_DAY } from "./verifiedAssistant";
import { SearchHealthController, observeSearchHealth, checkAnonSearchBudget, cachedHealthLevel, GLOBAL_HEALTH_DO_NAME } from "./searchHealth";
import { reportError, withErrorReporting, SentryEnv } from "./sentry";
import { isApiRootRequest, apiRootResponse } from "./apiRoot";
import { isApiKeysPath, apiKeysHowResponse, readApiKeysBody, apiKeysFacts, apiKeysRequest, ASK_FOR_A_KEY, UNKNOWN_KEY_MESSAGE, KEY_NOT_ACTIVATED_MESSAGE, API_KEYS_ENFORCED_MESSAGE, API_KEY_ASKS_PER_NETWORK_PER_DAY, API_KEY_ASKS_REFUSED_MESSAGE } from "./apiKeys";
import { wantsKeylessNotice, keylessNoticeFor, metaNoticeTransform } from "./keylessNotice";
import { contactBudgetFor, contactSpent, markContactSpent, contactBudgetMessage, CONTACT_PER_SECOND } from "./contactBudget";
import { loadEnforcement, matchEnforcement, enforceBucket, enforceSpent, markEnforceSpent, DEFAULT_SHARED_DAILY, ENFORCE_BLOCK_MESSAGE, ENFORCE_BUDGET_MESSAGE } from "./enforcementList";
import { perSecondLimitFor } from "./highRps";

export interface Env extends SentryEnv {
    HYPERDRIVE: Hyperdrive;
    RATE_LIMITER: DurableObjectNamespace;
    SEARCH_HEALTH: DurableObjectNamespace;
    ANALYTICS: AnalyticsEngineDataset;
    OPENALEX_API_URL: string;
    TEXT_API_URL: string;
    SEARCH_API_URL?: string;  // Optional - falls back to OPENALEX_API_URL if not set
    CONTENT_WORKER: Fetcher;  // Service binding to openalex-content-worker
    CV_PARSER?: Fetcher;
    QUERY_WRITER?: Fetcher;   // Service binding to openalex-query-writer: /query/text, plain words to OQL (oxjob #1494)
    QUERY_TEXT_ACCOUNTS?: string; // feature flag: user/org ids allowed to call /query/text (comma-separated); empty = nobody
    HIGH_RPS_ACCOUNTS?: string;   // user/org ids whose keys get a higher per-second cap, `id` or `id:rps` (oxjob #1689; highRps.ts)
    COLLECTION_PROXY_KEY?: string;  // Worker secret, same name and value as on users-api (oxjob #1515)
    AUTHOR_FIXES_URL?: string;   // openalex-author-fixes Heroku app (oxjob #1430)      // Service binding to openalex-cv-parser
    // oxjob #338 Phase 5a — the website token (Turnstile-minted; see uiToken.ts). Both optional:
    // if either is unset the feature is inert (no mint; every request is trustedUi=false,
    // priced and gated like any keyless call). Set as Worker secrets.
    TURNSTILE_SECRET?: string;       // Cloudflare Turnstile secret (siteverify)
    UI_TOKEN_HMAC_SECRET?: string;   // HMAC signing secret for the minted token
    // oxjob #521 WS-3: access key for GET /search-health. The ladder RULES are
    // public (this repo is), but the LIVE state is a free precision oracle for
    // anyone probing the API — so the endpoint 404s unless the caller presents
    // this key (?key= or X-Health-Key). Unset = endpoint disabled entirely.
    SEARCH_HEALTH_KEY?: string;      // Worker secret
    // oxjob #521 WS-3 Phase 1: manual override for the anon-search ladder.
    // GREEN|YELLOW|ORANGE|RED pins the enforcement level; unset = automatic
    // (health-driven). Replaces the retired SHED_ANON_SEARCH code flag —
    // FORCE_HEALTH_STATE=RED is the old armed shed, without a deploy.
    FORCE_HEALTH_STATE?: string;     // plain env var (keep_vars)
    // oxjob #521 WS-3 v3.5: Slack incoming-webhook URL for episode alerts
    // (ORANGE/RED engaged, RED escalation, recovered). Unset = alerts inert.
    SLACK_WEBHOOK_URL?: string;      // Worker secret
    // oxjob #1686: the value a Cloudflare Transform Rule puts on X-OpenAlex-Verified-Assistant for
    // Cloudflare-verified AI assistants (see verifiedAssistant.ts). Unset = feature off.
    VERIFIED_ASSISTANT_TOKEN?: string; // Worker secret
    // oxjob #1692: the private enforcement list (KV key "state") and where its shadow/enforce decisions are counted.
    // Unset = feature off (see enforcementList.ts).
    ENFORCEMENT?: KVNamespace;
    ENFORCE_AE?: AnalyticsEngineDataset;
}

// oxjob #338: minted UI-provenance tokens live 30 min; the GUI re-mints on expiry.
const UI_TOKEN_TTL_SECONDS = 1800;
// Header the GUI attaches the minted token on (mirrors getApiKeyFromRequest's
// header style). Chosen over a query param so it stays out of URL logs/cache
// keys and isn't copy-pasteable from a shared URL the way `mailto` was.
const UI_TOKEN_HEADER = "X-OpenAlex-UI";
// Set to "refresh" on the response when a request carried a token we refused (expired, minted on another
// network, or forged), so the website knows to mint a new one (oxjob #1691).
const UI_TOKEN_STATUS_HEADER = "X-OpenAlex-UI-Token";
// /ui-token mints per IP (oxjob #1691). A NAT'd campus shares one IP, hence the generous daily cap.
const UI_TOKEN_MINTS_PER_IP_PER_DAY = 500;
const UI_TOKEN_MINTS_PER_IP_PER_SECOND = 5;
// Requests whose UI token was refused; the default export adds UI_TOKEN_STATUS_HEADER to their responses.
const uiTokenRefused = new WeakSet<Request>();

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
    // A key an AI agent asked for, not yet activated by its person (oxjob #1697; api_keys_view.activation_pending).
    activationPending?: boolean;
    // The key whose daily bucket this key spends from, when not its own: an agent's key shares its account key's
    // day, so one person gets one free day (oxjob #1697/#1692; api_keys_view.budget_key).
    budgetKey?: string | null;
    cacheRefreshed?: boolean;
}

// In-memory cache for API key validation
const API_KEY_CACHE = new Map<string, ApiKeyAuth & { cachedAt: number }>();
const CACHE_TTL = 60000; // 60 seconds

// Pay→usable race recovery (oxjob #409). When a request would be 429'd because both
// the daily and prepaid pools look empty, we re-read the balance fresh from the DB
// once and retry — this catches the case where the user just bought prepaid credit
// but this isolate's cache still holds the pre-purchase balance. To stop a genuinely
// out-of-credits client from hammering the DB on every blocked request, we re-check
// at most once per key per TOPUP_RECHECK_TTL.
const TOPUP_RECHECK_TTL = 10000; // 10 seconds
const LAST_TOPUP_RECHECK = new Map<string, number>();

// oxjob #166. Distinct from the 'throttled' plan value (max_per_day=0).
const THROTTLE_MESSAGE = "Your access is temporarily throttled while we investigate unsustainable usage patterns. Please contact support@openalex.org for details.";

// ANON-SEARCH LADDER (oxjob #521 WS-3 Phase 1) — the health-gated anon class
// bucket that replaced the emergency SHED_ANON_SEARCH flag (retired 2026-07-02;
// it 503'd ALL keyless non-GUI works search while armed, 07-01→07-02). Keyless,
// non-GUI /works search now draws from ONE shared token bucket whose rate
// follows live search health (searchHealth.ts): GREEN = no limit (and no DO
// call on the healthy fast path), YELLOW = 60/s, ORANGE = 20/s, RED = off.
// Manual override: set the FORCE_HEALTH_STATE env var (RED = the old armed
// shed, no deploy needed). Enforcement lives below at the old shed site.

// Conversion: 1 credit = $0.0001 (10,000 credits = $1)
const CREDIT_TO_USD = 0.0001;

function creditsToUsd(credits: number): number {
    return Math.round(credits * CREDIT_TO_USD * 10000) / 10000; // 4 decimal places
}

export { RateLimiter };
export { SearchHealthController };

const handler = {
    async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        const startTime = Date.now();

        if (req.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: getCorsHeaders()
            });
        }

        // Author fixes (oxjob #1430): its own app, its own auth (site-wide keys),
        // no credits. Before the method gate because fixes use PATCH.
        if (env.AUTHOR_FIXES_URL && isAuthorFixesPath(new URL(req.url).pathname)) {
            const r = await fetch(await authorFixesRequest(req, env.AUTHOR_FIXES_URL));
            return addCorsHeaders(new Response(r.body, { status: r.status, headers: r.headers }));
        }

        // Collections (oxjob #1515): users-api serves them, with its own auth and access
        // checks, no credits. Before the method gate because they use PATCH and DELETE.
        if (isCollectionsPath(new URL(req.url).pathname)) {
            try {
                const r = await fetch(await collectionsRequest(req, USERS_API_URL, env.COLLECTION_PROXY_KEY));
                return addCorsHeaders(new Response(r.body, { status: r.status, headers: r.headers }));
            } catch {
                return json(502, { error: "Bad Gateway", code: "unavailable", message: "Collections are unavailable right now. Try again in a minute." });
            }
        }

        // Keys an AI agent asks for (oxjob #1697; see apiKeys.ts): free, before every budget gate.
        if (isApiKeysPath(new URL(req.url).pathname)) {
            return addCorsHeaders(await apiKeysRoute(req, env, ctx, startTime));
        }

        if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "POST") {
            return addCorsHeaders(new Response("Method Not Allowed", { status: 405 }));
        }

        const url = new URL(req.url);

        // robots.txt for every hostname this proxy serves (api.openalex.org,
        // content.openalex.org). Sits before API-key validation so compliant
        // crawlers get a real 200 text/plain answer and are billed nothing —
        // it used to fall through to the API 404 and cost a credit (oxjob #701).
        if (url.pathname === "/robots.txt") {
            return addCorsHeaders(new Response("User-agent: *\nAllow: /\n", {
                headers: { "Content-Type": "text/plain; charset=utf-8" }
            }));
        }

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

        // UI-provenance token mint (oxjob #338 Phase 5a). The GUI POSTs a
        // Cloudflare Turnstile solve; we verify it server-side and mint a
        // short-TTL HMAC token the GUI then sends back on the X-OpenAlex-UI
        // header. No API key needed (anonymous SPA), so it sits before API-key
        // validation, like /cv-parse. This endpoint ONLY issues a provenance
        // marker — it grants no quota or access, so a failed/absent mint just
        // means the GUI's later requests are tagged untrusted, never blocked.
        const uiTokenPath = url.pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
        if (uiTokenPath === 'ui-token') {
            if (req.method !== 'POST') {
                return json(405, { error: "Method Not Allowed", message: "POST a Turnstile token to /ui-token" });
            }
            if (!env.TURNSTILE_SECRET || !env.UI_TOKEN_HMAC_SECRET) {
                // Feature not provisioned yet — say so plainly; the GUI treats a
                // non-200 here as "no UI token this session" and carries on.
                return json(503, { error: "UI token minting not configured" });
            }
            let turnstileResponse: string | null = null;
            try {
                const body = await req.json() as { turnstileResponse?: string; "cf-turnstile-response"?: string };
                turnstileResponse = body.turnstileResponse || body["cf-turnstile-response"] || null;
            } catch { /* fall through to the missing-token branch */ }

            const mintIp = req.headers.get("CF-Connecting-IP");
            // Mints per IP are capped (oxjob #1691): a browser mints about once per visit; a script minting
            // hundreds is not the website. Over the cap the website just goes without a token (no perks).
            // Checked before siteverify so a flood never reaches Cloudflare's API. Fails open on DO errors.
            try {
                const mintLimiter = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(`uimint:${mintIp || "anon"}`));
                const mintCheck = await mintLimiter.fetch("http://internal/check", {
                    method: "POST",
                    body: JSON.stringify({ dailyLimit: UI_TOKEN_MINTS_PER_IP_PER_DAY, perSecondLimit: UI_TOKEN_MINTS_PER_IP_PER_SECOND, credits: 1 }),
                }).then(r => r.json() as Promise<{ success: boolean; retryAfter?: number }>);
                if (!mintCheck.success) {
                    const tooMany = json(429, { error: "Too many UI token requests from this IP" });
                    tooMany.headers.set("Retry-After", String(Math.ceil(mintCheck.retryAfter ?? 3600)));
                    return tooMany;
                }
            } catch (error) {
                reportError(error, { site: "ui_token_mint_limit" });
            }
            const ts = await verifyTurnstile(turnstileResponse, env.TURNSTILE_SECRET, mintIp);
            if (!ts.success) {
                return json(403, { error: "Turnstile verification failed", errorCodes: ts.errorCodes });
            }
            const token = await mintUiToken(env.UI_TOKEN_HMAC_SECRET, Date.now(), UI_TOKEN_TTL_SECONDS, mintIp);
            return json(200, { token, expiresIn: UI_TOKEN_TTL_SECONDS });
        }

        // oxjob #521 WS-3 Phase 0: read-only view of the search-health monitor
        // (observe-only — it enforces nothing; see searchHealth.ts). Key-gated:
        // the live state is a feedback oracle an abuser could watch while
        // pushing load. The static rules are public (this repo is), but the
        // real-time state needn't be free. 404 on miss/unset so the endpoint
        // doesn't advertise itself.
        if (uiTokenPath === 'search-health' && req.method === 'GET') {
            const presented = url.searchParams.get('key') || req.headers.get('X-Health-Key');
            if (!env.SEARCH_HEALTH_KEY || presented !== env.SEARCH_HEALTH_KEY) {
                return json(404, { error: "Not found" });
            }
            try {
                const stub = env.SEARCH_HEALTH.get(env.SEARCH_HEALTH.idFromName(GLOBAL_HEALTH_DO_NAME));
                if (url.searchParams.has('test-slack')) {
                    const testResp = await stub.fetch('http://internal/test-slack', { method: 'POST' });
                    return json(testResp.status, await testResp.json());
                }
                const stateResp = await stub.fetch('http://internal/state');
                return json(stateResp.status, await stateResp.json());
            } catch {
                return json(503, { error: "search-health monitor unavailable" });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // GUI FRONT-PAGE AUTOCOMPLETE COMBO — ad-hoc, NON-REST, GUI-only.
        //
        // This deliberately breaks REST: it addresses no OpenAlex resource. It
        // exists to optimize exactly ONE interaction — the autocomplete dropdown
        // under the big search box on the openalex.org front page (basic search).
        // That dropdown needs four suggestion lists at once (author names,
        // institution names, keyword concepts, work titles). The GUI used to
        // fetch them as FOUR parallel requests per keystroke-pause. Anonymous
        // clients are capped at 10 req/s (perSecondLimit, below), so a fast
        // typist's bursts (4 calls × a few pauses/sec) tripped that cap — and
        // because the SPA renders any logged-out 429 as the daily-credit modal,
        // it popped a scary "you've hit today's free limit" dialog mid-typing,
        // even though NO credits were spent (it was the per-second throttle).
        //
        // Collapsing the four into ONE request per pause keeps the dropdown well
        // under 10 req/s. We fan out to origin server-side and merge. It's free
        // (0 credits) and sits BEFORE the rate limiter, like /ui-token: a single
        // client request that can't trip the per-second cap.
        //
        // "GUI-only" is intent, not enforcement — any caller may hit it, which is
        // fine: it does no more than four already-public, already-free calls,
        // bundled. Keep it dumb and cheap. If you ever want a general, RESTful
        // multi-entity autocomplete, design that separately — this is a pragmatic
        // hack for one specific UI, not that.
        // ─────────────────────────────────────────────────────────────────────
        if (uiTokenPath === 'gui/autocomplete') {
            if (req.method !== 'GET') {
                return json(405, { error: "Method Not Allowed", message: "GET /gui/autocomplete?q=..." });
            }
            const q = (url.searchParams.get('q') || '').trim();
            if (!q) {
                return json(200, { authors: [], institutions: [], keywords: [], works: [] });
            }
            // Works titles are only wanted once the query is a few words long
            // (the GUI passes works=0 for short queries) — skip that upstream call.
            const includeWorks = url.searchParams.get('works') !== '0';

            const trim = (s: string) => s.replace(/\/+$/, '');
            const searchOrigin = trim(env.SEARCH_API_URL || env.OPENALEX_API_URL);
            const apiOrigin = trim(env.OPENALEX_API_URL);
            const eq = encodeURIComponent(q);
            const SELECT = 'id,display_name,works_count';
            const MAILTO = 'mailto=ui@openalex.org';

            // Each source fails soft to [] so one slow/broken upstream can't blank
            // the whole dropdown. author/institution use the light entity-search
            // shape (per_page≤10 + select) the GUI already sent; keyword/work use
            // the /autocomplete/* endpoints.
            const sub = async (u: string): Promise<unknown[]> => {
                try {
                    const r = await fetch(u, {
                        headers: { "User-Agent": "OpenAlex-Proxy/1.0", "Accept": "application/json" },
                        signal: AbortSignal.timeout(9000),
                    });
                    if (!r.ok) return [];
                    const j = await r.json() as { results?: unknown[] };
                    return Array.isArray(j.results) ? j.results : [];
                } catch { return []; }
            };

            const [authors, institutions, keywords, works] = await Promise.all([
                sub(`${searchOrigin}/authors?search=${eq}&per_page=10&select=${SELECT}&${MAILTO}`),
                sub(`${searchOrigin}/institutions?search=${eq}&per_page=10&select=${SELECT}&${MAILTO}`),
                sub(`${apiOrigin}/autocomplete/keywords?q=${eq}&${MAILTO}`),
                includeWorks
                    ? sub(`${apiOrigin}/autocomplete/works?q=${eq}&${MAILTO}`)
                    : Promise.resolve([] as unknown[]),
            ]);

            return json(200, { authors, institutions, keywords, works });
        }

        // Is this request carrying a valid website token, minted on this request's network? It tags
        // analytics (double7) and earns the website's perks (see uiToken.ts); it never blocks a request.
        const uiTokenHeader = req.headers.get(UI_TOKEN_HEADER);
        const uiTokenVerify = await verifyUiToken(
            uiTokenHeader,
            env.UI_TOKEN_HMAC_SECRET,
            Date.now(),
            req.headers.get("CF-Connecting-IP"),
        );
        const trustedUi = uiTokenVerify.valid;
        if (uiTokenHeader && !trustedUi && uiTokenVerify.reason !== "no_secret") uiTokenRefused.add(req);

        const apiKey = getApiKeyFromRequest(req);
        let hasValidApiKey = false;

        // Changefiles browsing: tolerate placeholder keys (e.g., "YOUR_API_KEY")
        // without a 401 so users can browse available files without a real key.
        // Path matching lives in changefilesPaths.ts (shared with the classifier
        // and download gate so they can't drift — zd#8865).
        const isChangefilesBrowse = isChangefilesBrowsePath(url.pathname);
        // TODO Feb 13, 2026: Change these to 100 to require API key for normal usage.
        // 2026-01-26: Reduced from 100K to 10K during API slowdown incident to shift capacity to API key holders.
        // 2026-06-20: Reduced 10K→1K (keyless $1.00→$0.10/day) — restores Alice's never-shipped
        // intended keyless budget; makes a key a real 10× edge. Shaves ~52% of keyless ES load
        // with ~2-user real-GUI collateral (oxjob #479 blast-radius read). With list=1 credit,
        // keyless users can make 1K list requests/day without an API key.
        // 2026-10-14: Cloudflare-verified AI assistants (claude.ai, ChatGPT, Mistral, Perplexity fetching for a
        // person) get 5M ($500) a day per IP in a bucket of their own (oxjob #1686; see verifiedAssistant.ts).
        const verifiedAssistant = isVerifiedAssistant(apiKey, req.headers.get(VERIFIED_ASSISTANT_HEADER), env.VERIFIED_ASSISTANT_TOKEN);
        let maxPerDay = verifiedAssistant ? VERIFIED_ASSISTANT_CREDITS_PER_DAY : 1000;  // Default daily rate limit for unauthenticated users
        let maxCreditsPerDay = maxPerDay;  // Default credits for unauthenticated users (1:1)
        let isGrandfathered = false;  // Unauthenticated users are not grandfathered

        let onetimeCreditsBalance = 0;
        let onetimeCreditsExpiresAt: string | undefined;
        let userPlan: string | null = null;
        // The key's account (a user id, or an org id for org keys); read by the /query/text feature flag (oxjob #1494)
        // and the per-second cap override (oxjob #1689).
        let keyAccountIds: string[] = [];
        // True when the auth (and thus the prepaid balance below) came from the
        // per-isolate API_KEY_CACHE rather than a fresh DB read. Used by the
        // pay→usable race recovery on the 429 path (oxjob #409).
        let usedCachedAuth = false;
        let activationPending = false;  // oxjob #1697
        let budgetKey: string | null = null;  // oxjob #1697: the key whose daily bucket this one spends from

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
                keyAccountIds = [authResult.userId, authResult.orgId].filter((x): x is string => Boolean(x));
                activationPending = authResult.activationPending === true;
                budgetKey = authResult.budgetKey ?? null;
                // cacheRefreshed === true means we just read the DB; false/undefined
                // means this balance came from the (≤60s, per-isolate) cache.
                usedCachedAuth = authResult.cacheRefreshed !== true;

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
                        reportError(error, { site: "rate_throttle_do" });
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

        // The API root, served here: free, never refused for budget (oxjob #1686; see apiRoot.ts). After the key
        // check, so a bad key on "/" still gets its 401 (people test their key there); before every gate and charge.
        if (isApiRootRequest(url, req.method)) {
            logAnalytics({
                ctx, env, apiKey, req, url, scope: 'root',
                responseTime: Date.now() - startTime,
                statusCode: 200, rateLimit: 0, rateLimitRemaining: 0,
                endpointType: 'list', creditCost: 0, trustedUi,
            });
            return addCorsHeaders(apiRootResponse(req.method));
        }

        // Two key states (oxjob #1697, Jason 2026-10-15): a key an AI agent asked for works only once its person has
        // clicked the emailed activation link. Until then it is refused here, with the way out, before any budget.
        if (activationPending) {
            logAnalytics({
                ctx, env, apiKey, req, url, scope: 'not_activated',
                responseTime: Date.now() - startTime,
                statusCode: 403, rateLimit: 0, rateLimitRemaining: 0, creditCost: 0,
            });
            return json(403, { error: "Forbidden", code: "key_not_activated", message: KEY_NOT_ACTIVATED_MESSAGE });
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

        // Keyless cursor paging past the first page needs a free key (oxjob #1682; see src/cursorGate.ts).
        // Gated before the rate limiter, so a refused page burns no credits and never reaches ES.
        if (isKeylessCursorPage(url, hasValidApiKey, trustedUi)) {
            const errorResponse = json(401, KEYLESS_CURSOR_ERROR);
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
                rateLimitRemaining: 0,
            });
            return errorResponse;
        }

        // Search-text VOLUME gate (oxjob #340). Reject free-tier requests whose
        // `search=` value is pathologically long (pasted abstracts / LLM-agent
        // prompts / the 2026-05-05 "ray" essay-OR shape) — intrinsic ES `took`
        // is driven by scored-text volume, not Boolean count. Exempts paid plans
        // + the unforgeable #338 trustedUi token; keys ONLY on the search value
        // length (filter-pipe OR-of-IDs is cheap and untouched). Gated here,
        // before the rate limiter, so a rejected request burns no credits and
        // never reaches ES. See src/searchVolumeGate.ts.
        if (req.method !== "POST") {
            const volume = checkSearchVolume(url, {
                hasValidApiKey,
                plan: userPlan,
                trustedUi,
                paidPlans: ENTERPRISE_PLANS,
            });
            if (volume.gated) {
                const errorResponse = new Response(JSON.stringify({
                    error: "Search query too long",
                    error_source: "openalex-api-proxy",
                    message: searchVolumeMessage(volume.length),
                }), {
                    status: 400,
                    headers: {
                        "Content-Type": "application/json",
                        "x-openalex-edge-reject": "search_volume",
                        ...Object.fromEntries(getCorsHeaders()),
                    },
                });
                logAnalytics({
                    ctx, env, apiKey, req, url, scope: 'main',
                    responseTime: Date.now() - startTime,
                    statusCode: 400, rateLimit: 0, rateLimitRemaining: 0,
                });
                return errorResponse;
            }
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
            return await handleRateLimitEndpoint(req, env, apiKey, hasValidApiKey, maxCreditsPerDay, isGrandfathered, onetimeCreditsBalance, onetimeCreditsExpiresAt, budgetKey);
        }

        // rerank (oxjob #1521): `rerank=true` in the URL, or `"rerank": true` in a POST body (the
        // OQL door). It adds RERANK_CREDITS to the request's price. While the search-health ladder
        // is at YELLOW or above it is dropped instead, so rerank never adds load to a struggling
        // cluster; the request then runs in its normal order at the normal price.
        let rerankAsked = isRerank(url.searchParams);
        let rewrittenPostBody: string | null = null;
        // The POST body, parsed once: for rerank here and for the sync-field gate (oxjob #1689) below.
        let postBody: unknown = null;
        if (req.method === "POST") {
            try { postBody = JSON.parse(await req.clone().text()); } catch { /* not JSON: nothing to price or gate */ }
        }
        if (!rerankAsked && bodyAsksRerank(postBody)) {
            rerankAsked = true;
            if (cachedHealthLevel(env) >= 1) {
                const parsed = postBody as Record<string, unknown>;
                delete parsed.rerank;
                rewrittenPostBody = JSON.stringify(parsed);
            }
        }
        if (rerankAsked && cachedHealthLevel(env) >= 1) {
            url.searchParams.delete('rerank');
            rerankAsked = false;
        }

        // Sync filters through OQL/OQO (oxjob #1689; see syncGate.ts): armed for a caller without a paid plan whose
        // OQL/OQO could name one, and checked once the origin answers, against the engine's own translation.
        const oqlText = requestOqlText(url.searchParams, postBody);
        const syncGateArmed = oqlText !== null && mightNameSyncField(oqlText)
            && !(userPlan !== null && ENTERPRISE_PLANS.has(userPlan));

        // Only the website token says a request came from openalex.org; an Origin or Referer is forgeable
        // and stopped counting on 2026-10-15 (oxjobs #1691, #1692).
        // Classify endpoint and determine credit cost
        const classification = classifyEndpoint(url.pathname, url.searchParams, { websiteFacet: trustedUi });
        // Grandfathered users get search at 1 credit instead of 10; rerank adds RERANK_CREDITS for everyone
        const creditCost = ((isGrandfathered && classification.type === 'search') ? 1 : classification.creditCost)
            + rerankCredits(classification.type, rerankAsked);

        // /query/text runs a model on our account, so it needs the caller's own key (no shared anonymous pool),
        // checked before anything is held (oxjob #1494).
        if (classification.type === 'query_text' && !hasValidApiKey) {
            return json(401, {
                error: "API key required",
                message: "Writing a query from plain words uses a language model and needs your own API key. Get one free at https://openalex.org/users, then send it as an \"Authorization: Bearer YOUR_KEY\" header.",
            });
        }
        // Feature flag: /query/text answers only the accounts listed in QUERY_TEXT_ACCOUNTS (user or org ids,
        // comma-separated); everyone else gets a free 403 while it is in testing (Jason, 2026-10-11).
        if (classification.type === 'query_text' && !queryTextAllowed(env.QUERY_TEXT_ACCOUNTS, keyAccountIds)) {
            return json(403, {
                error: "Not available yet",
                message: "Writing queries from plain words is in testing and not open yet. Nothing was charged.",
            });
        }

        // ANON-SEARCH LADDER enforcement (oxjob #521 WS-3 Phase 1; see the
        // comment at the top of the file and searchHealth.ts). Website traffic (trustedUi)
        // is carved out.
        // Scope: /works search only — the recurring saturation driver. Search on
        // other entities (/authors, /sources, …) is not gated by the ladder.
        // Runs BEFORE the credits DO, so rejected requests are edge-cheap and
        // never charged. Untouched: keyed clients, the GUI, autocomplete (cheap
        // 'list'), singleton/list, semantic (already 1/s capped).
        const isWorksSearch = url.pathname.replace(/^\/+/, "").split("/")[0].toLowerCase() === "works";
        if (isWorksSearch && !apiKey && !trustedUi && classification.type === 'search') {
            const verdict = await checkAnonSearchBudget(env, ctx);
            if (!verdict.ok) {
                const statusCode = verdict.statusCode ?? 503;
                const retryAfter = verdict.retryAfter ?? 60;
                logAnalytics({
                    ctx, env, apiKey, req, url,
                    scope: 'anon-search-ladder',
                    responseTime: Date.now() - startTime,
                    statusCode,
                    rateLimit: maxCreditsPerDay,
                    rateLimitRemaining: 0,
                    endpointType: classification.type,
                    creditCost: 0,
                    trustedUi
                });
                const body = statusCode === 503 ? {
                    error: "Search temporarily unavailable",
                    message: "Anonymous search is paused while the search cluster recovers from heavy load. " +
                        "Please retry shortly, or use a free API key for uninterrupted access: https://openalex.org/rest-api.",
                } : {
                    error: "Rate limit exceeded",
                    message: "Anonymous search is temporarily rate-limited while the search cluster is under elevated load. " +
                        `Please retry in ${retryAfter}s, or use a free API key for uninterrupted access: https://openalex.org/rest-api.`,
                    retryAfter,
                };
                const resp = json(statusCode, body);
                const headers = new Headers(resp.headers);
                headers.set("Retry-After", String(retryAfter));
                return new Response(resp.body, { status: statusCode, headers });
            }
        }

        // Use unified credits-based rate limiting
        const scope = "credits";
        const ip = req.headers.get("CF-Connecting-IP");
        // A verified assistant's budget is its own (oxjob #1686): it never spends, or is blocked by, the
        // ordinary keyless budget of the IP it shares.
        // Ordinary keyless budgets are per network, not per address (oxjob #1692): an IPv6 /64 belongs to
        // one household or device and holds 2^64 addresses, so per address it bought a fresh budget per
        // request (14 Oct: 1,123 /64s took 3.33M credits over 39K addresses). IPv4 stays per address.
        // An agent's key spends from its account key's bucket (budgetKey; oxjob #1697): one free day per person.
        const identifier = (apiKey && (budgetKey || apiKey)) || (verifiedAssistant ? ip : networkOf(ip) ?? ip) || "anon";
        const rateLimitKey = verifiedAssistant ? `${scope}:verified-assistant:${identifier}` : `${scope}:${identifier}`;
        const limit = maxCreditsPerDay;

        // oxjob #521 follow-up: tiered per-second cap. Free/anonymous clients burst
        // far above sustainable rates during saved-search batches (peaks of 100-700/s
        // observed in the 2026-06-27 incidents); paid plans get more headroom. 50/s
        // still exceeds every paid plan's daily budget, so it only smooths burst
        // spikes, never caps daily throughput. Thresholds mirror the daily credit
        // ceilings: paid (>10k) 50/s, free-registered (10k) 30/s, anon (default 1k)
        // and throttled plans (max=0) 10/s. 2026-07-01: anon dropped 30→10/s — anon
        // is the dominant diffuse load during search-saturation incidents; the 10/s
        // per-IP cap reins in the heavy-hitter anon IPs without touching keyed clients.
        // 2026-10-14: verified AI assistants (5M a day, oxjob #1686) land on 50/s through the same rule.
        // 2026-10-15: keys of accounts listed in HIGH_RPS_ACCOUNTS get their own cap instead, default 500/s: the
        // website's server-rendering key (oxjob #1689; see highRps.ts).
        const perSecondLimit = perSecondLimitFor(maxCreditsPerDay, keyAccountIds, env.HIGH_RPS_ACCOUNTS);

        // Check rate limit using Durable Object
        const id = env.RATE_LIMITER.idFromName(rateLimitKey);
        const limiter = env.RATE_LIMITER.get(id);

        // One semantic search a second per client; a refetch of the same search
        // (another page size or page) within that second passes (semanticGate.ts).
        if (classification.type === 'semantic') {
            try {
                const semanticCheck = await limiter.fetch("http://internal/check-semantic", {
                    method: "POST",
                    body: JSON.stringify({ dailyLimit: limit, search: semanticSearchKey(url) })
                }).then(res => res.json() as Promise<{ success: boolean; retryAfter?: number }>);

                if (!semanticCheck.success) {
                    const retryAfter = Math.ceil(semanticCheck.retryAfter || 1);
                    const errorResponse = new Response(JSON.stringify({
                        error: "Rate limit exceeded",
                        message: `Semantic search is limited to 1 search per second. Please wait and try again.`,
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
                reportError(error, { site: "semantic_rate_limit_do" });
            }
        }

        // oxjob #521: throttle broad boolean searches (>5 OR/AND/NOT operators)
        // per client. These are the bursty, ES-thread-saturating queries;
        // the limit binds on the handful of high-rate senders, not interactive users.
        // Lowered from >10 to >5 (2026-06-27): the 6-10-operator cohort (cardiovascular/
        // systematic-review monitors) was slipping under the old threshold and saturating
        // the search thread pool. Interactive queries rarely exceed 5 operators.
        // 2026-07-16: valid-key clients lifted to 5 req/s; anonymous stays at 1 req/s.
        // 2026-07-24 (oxjob #677): paid plans lifted to 25 req/s — on the post-#469
        // cluster these queries mean ~150-330ms took (not seconds), and 5 req/s was
        // rejecting real production traffic from premium customers (Nestlé zd#22825,
        // French Ministry, firstignite). Worst-case single-client burst at 25 req/s
        // ≈ 4-8 concurrent mean-cost searches; the 5s ES timeout + 9s abort backstop
        // remain the pathological-query defense.
        const booleanOperators = classification.type === 'search'
            ? countBooleanOperators(url.searchParams) : 0;
        if (booleanOperators > 5) {
            const hasPaidPlan = userPlan !== null && ENTERPRISE_PLANS.has(userPlan);
            const booleanRatePerSec = hasPaidPlan ? 25 : hasValidApiKey ? 5 : 1;
            try {
                const booleanCheck = await limiter.fetch("http://internal/check-boolean", {
                    method: "POST",
                    body: JSON.stringify({ dailyLimit: limit, intervalMs: 1000 / booleanRatePerSec })
                }).then(res => res.json() as Promise<{ success: boolean; retryAfter?: number }>);

                if (!booleanCheck.success) {
                    const retryAfter = Math.ceil(booleanCheck.retryAfter || 1);
                    const keyHint = hasPaidPlan
                        ? ""
                        : hasValidApiKey
                            ? " Paid plans get 25 requests per second (https://openalex.org/pricing)."
                            : " Clients with an API key get 5 requests per second (free at https://openalex.org/rest-api); paid plans get 25.";
                    const errorResponse = new Response(JSON.stringify({
                        error: "Rate limit exceeded",
                        message: `Your query uses ${booleanOperators} boolean operators (OR/AND/NOT). ` +
                            `Broad boolean searches are heavy for our search cluster, so queries with more ` +
                            `than 5 operators are limited to ${booleanRatePerSec} request${booleanRatePerSec === 1 ? "" : "s"} per second per client.${keyHint} ` +
                            `Please wait ${retryAfter}s and retry, space out these requests, or narrow the query ` +
                            `(fewer OR/AND/NOT terms). See https://docs.openalex.org/how-to-use-the-api/rate-limits-and-authentication`,
                        reason: "broad_boolean_query",
                        booleanOperators,
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
                console.error("Boolean rate limit check error:", error);
                reportError(error, { site: "boolean_rate_limit_do" });
            }
        }

        // oxjob #876 (2026-09-14): throttle filter OR-lists with >10 distinct terms on a
        // wide field (topics/concepts) to 1 req/s per client, every tier. One prepaid key
        // sweeping /works with 100-term topics.id filters (2-5s ES took each, ~7 req/s)
        // saturated every search thread on the cluster; it was a keyed list call, so
        // the boolean throttle, search pricing and the anon ladder all missed it.
        // Cost scales with distinct wide terms, not clause count — identifier OR-lists
        // (doi, openalex ids) are exempt by construction. Flat 1 req/s because at
        // ~144 thread-seconds per request even 2 req/s is a quarter of the cluster.
        const wideOr = countWideOrTerms(url.searchParams);
        if (wideOr.count > WIDE_OR_MAX_TERMS) {
            try {
                const wideOrCheck = await limiter.fetch("http://internal/check-wide-or", {
                    method: "POST",
                    body: JSON.stringify({ intervalMs: 1000 })
                }).then(res => res.json() as Promise<{ success: boolean; retryAfter?: number }>);

                if (!wideOrCheck.success) {
                    const retryAfter = Math.ceil(wideOrCheck.retryAfter || 1);
                    const errorResponse = new Response(JSON.stringify({
                        error: "Rate limit exceeded",
                        message: `Your filter ORs ${wideOr.count} values on ${wideOr.field}. ` +
                            `Each ${wideOr.field} value matches a large share of the index, so OR-lists longer ` +
                            `than ${WIDE_OR_MAX_TERMS} terms are limited to 1 request per second per client. ` +
                            `Please wait ${retryAfter}s and retry, or split the list into requests of at most ` +
                            `${WIDE_OR_MAX_TERMS} ${wideOr.field} values each. ` +
                            `See https://docs.openalex.org/how-to-use-the-api/rate-limits-and-authentication`,
                        reason: "wide_or_filter",
                        field: wideOr.field,
                        orTerms: wideOr.count,
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
                        ctx, env, apiKey, req, url, scope: 'wide_or', // blob5 — so these 429s are countable in AE
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
                console.error("Wide OR rate limit check error:", error);
                reportError(error, { site: "wide_or_rate_limit_do" });
            }
        }

        // A keyless contact address (mailto=) shares one budget across every IP that sends it (oxjob #1692; see
        // contactBudget.ts). An address whose day is spent is refused here, before any DO call or IP charge.
        const contact = await contactBudgetFor(url.searchParams, { apiKey, trustedUi, verifiedAssistant });
        const contactRefusal = (status: number, retryAfter: number, message: string) => {
            logAnalytics({
                ctx, env, apiKey, req, url, scope: 'contact',
                responseTime: Date.now() - startTime,
                statusCode: status,
                rateLimit: contact!.dailyLimit,
                rateLimitRemaining: 0,
                endpointType: classification.type,
                creditCost: 0,
            });
            const resp = json(status, { error: "Rate limit exceeded", message, retryAfter });
            resp.headers.set("Retry-After", String(Math.ceil(retryAfter)));
            return resp;
        };
        if (contact && contactSpent(contact.bucket, Date.now())) {
            return contactRefusal(429, getSecondsUntilMidnightUTC(), contactBudgetMessage());
        }

        // The private enforcement list (oxjob #1692; see enforcementList.ts): keyless traffic only. In shadow mode it
        // records what an entry would refuse (ENFORCE_AE) and changes nothing.
        const enforceHit = (!apiKey && !trustedUi && !verifiedAssistant)
            ? await matchEnforcement(await loadEnforcement(env.ENFORCEMENT, Date.now()), {
                ua: req.headers.get("User-Agent") || "",
                mailto: url.searchParams.get("mailto"),
                refererHost: refererHostOf(req.headers.get("Referer")),
                ip: req.headers.get("CF-Connecting-IP"),
                asn: typeof (req as { cf?: { asn?: unknown } }).cf?.asn === "number" ? (req as { cf?: { asn?: number } }).cf!.asn! : null,
            }, Date.now())
            : null;
        let enforceSettled = false;  // logged once per request, refuse or pass
        const enforceDecision = (refuse: boolean): Response | null => {
            enforceSettled = true;
            try {
                env.ENFORCE_AE?.writeDataPoint({
                    indexes: [enforceHit!.entry.id],
                    blobs: [enforceHit!.entry.id, enforceHit!.entry.action, enforceHit!.mode, classification.type, refuse ? "refuse" : "pass"],
                    doubles: [creditCost],
                });
            } catch { /* analytics never blocks */ }
            if (!refuse || enforceHit!.mode !== "enforce") return null;
            const block = enforceHit!.entry.action === "block";
            logAnalytics({
                ctx, env, apiKey, req, url, scope: 'enforce',
                responseTime: Date.now() - startTime,
                statusCode: block ? 403 : 429,
                rateLimit: 0, rateLimitRemaining: 0, endpointType: classification.type, creditCost: 0,
            });
            const resp = json(block ? 403 : 429, { error: block ? "Forbidden" : "Rate limit exceeded", message: block ? ENFORCE_BLOCK_MESSAGE : ENFORCE_BUDGET_MESSAGE });
            if (!block) resp.headers.set("Retry-After", String(getSecondsUntilMidnightUTC()));
            return resp;
        };
        if (enforceHit && (enforceHit.entry.action === "block" || enforceSpent(enforceBucket(enforceHit), Date.now()))) {
            const refusal = enforceDecision(true);
            if (refusal) return refusal;
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
                body: JSON.stringify({ dailyLimit: limit, perSecondLimit, credits: creditCost, onetimeBalance: onetimeCreditsBalance })
            }).then(res => res.json());
        } catch (error) {
            // If DO fails, allow the request through but log the error
            console.error("Rate limiter DO error:", error);
            reportError(error, { site: "rate_limiter_do" });
            rateLimitResult = { success: true, remaining: limit, creditsUsed: creditCost, onetimeRemaining: onetimeCreditsBalance };
        }

        // Pay→usable race recovery (oxjob #409). A daily-pool-exhausted 429 with a
        // cached balance might be wrong: the user may have just bought prepaid credit
        // that this isolate's API_KEY_CACHE hasn't picked up yet (TTL ≤60s, per-isolate).
        // Re-read the balance fresh from the DB once and retry the check. Safe because
        // the failed /check above hit the "both pools exhausted" branch, which returns
        // before consuming anything — so the retry can't double-charge. Throttled per
        // key so a genuinely-empty client can't hammer the DB on every blocked request.
        if (!rateLimitResult.success
            && rateLimitResult.limitType === 'daily'
            && apiKey
            && usedCachedAuth) {
            const lastRecheck = LAST_TOPUP_RECHECK.get(apiKey) ?? 0;
            if (Date.now() - lastRecheck >= TOPUP_RECHECK_TTL) {
                LAST_TOPUP_RECHECK.set(apiKey, Date.now());
                // Opportunistic cap so the throttle map can't grow unbounded per isolate.
                if (LAST_TOPUP_RECHECK.size > 10000) LAST_TOPUP_RECHECK.clear();
                API_KEY_CACHE.delete(apiKey);
                const freshAuth = await checkApiKey(req, env);
                const freshOnetime = freshAuth.valid ? (freshAuth.onetimeCreditsBalance ?? 0) : onetimeCreditsBalance;
                if (freshAuth.valid && freshOnetime > onetimeCreditsBalance) {
                    onetimeCreditsBalance = freshOnetime;
                    onetimeCreditsExpiresAt = freshAuth.onetimeCreditsExpiresAt;
                    try {
                        rateLimitResult = await limiter.fetch("http://internal/check", {
                            method: "POST",
                            body: JSON.stringify({ dailyLimit: limit, perSecondLimit, credits: creditCost, onetimeBalance: onetimeCreditsBalance })
                        }).then(res => res.json());
                    } catch (error) {
                        console.error("Rate limiter DO error (post-topup recheck):", error);
                        reportError(error, { site: "rate_limiter_do_topup_recheck" });
                    }
                }
            }
        }

        // Handle rate limit exceeded
        if (!rateLimitResult.success) {
            const isPerSecond = rateLimitResult.limitType === 'per_second';
            const costUsd = creditsToUsd(creditCost);
            const dailyRemainingUsd = creditsToUsd(rateLimitResult.remaining ?? 0);
            const prepaidRemainingUsd = creditsToUsd(rateLimitResult.onetimeRemaining ?? 0);

            let message: string;
            if (isPerSecond) {
                message = `Rate limit exceeded: ${perSecondLimit} requests per second. Please slow down.`;
            } else if (!apiKey) {
                // Anonymous: the exhausted budget is the free per-IP one, shared by
                // everyone behind the same NAT (an office, a campus). Say so, and say
                // the way out is the caller's OWN key — most people who hit this
                // already have one and just didn't send it (oxjob #1245: a GUI
                // "View in API" tab opened without a key while the user's battery
                // icon showed 95% left).
                message = `Insufficient budget. This request has no API key, so it counts against the free daily budget shared by everyone on your network's IP address, and that budget is used up ($${dailyRemainingUsd} remaining; resets at midnight UTC). Use your own key instead: add ?api_key=YOUR_KEY to the URL, or send it as an "Authorization: Bearer YOUR_KEY" header. Keys are free and have their own budget: https://help.openalex.org/api/authentication/ ${ASK_FOR_A_KEY}`;
            } else if (classification.type === 'query_text') {
                message = `Insufficient budget. Writing a query from plain words costs what the language model costs (usually $0.02-0.05) and needs some budget left; you have $${dailyRemainingUsd} daily budget and $${prepaidRemainingUsd} prepaid balance remaining. Daily budget resets at midnight UTC. Add funds at https://openalex.org/pricing`;
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

        // The IP's budget allowed it; now the contact address's shared one (fails open, like the IP check).
        if (contact) {
            try {
                const verdict = await env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(contact.bucket)).fetch("http://internal/check", {
                    method: "POST",
                    body: JSON.stringify({ dailyLimit: contact.dailyLimit, perSecondLimit: CONTACT_PER_SECOND, credits: creditCost }),
                }).then(r => r.json() as Promise<{ success: boolean; retryAfter?: number; limitType?: string }>);
                if (!verdict.success) {
                    if (verdict.limitType === 'per_second') {
                        return contactRefusal(429, verdict.retryAfter ?? 1,
                            `Rate limit exceeded: keyless requests naming this mailto address share ${CONTACT_PER_SECOND} requests per second across every network that sends them. Please slow down, or use a free API key: https://help.openalex.org/api/authentication/`);
                    }
                    markContactSpent(contact.bucket, Date.now());
                    return contactRefusal(429, getSecondsUntilMidnightUTC(), contactBudgetMessage());
                }
            } catch (error) {
                reportError(error, { site: "contact_budget_do" });
            }
        }

        // An enforcement-list shared budget (shadow counts in its own bucket, so shadow numbers are real numbers).
        if (enforceHit && !enforceSettled) {
            const bucket = enforceBucket(enforceHit);
            try {
                const verdict = await env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(bucket)).fetch("http://internal/check", {
                    method: "POST",
                    body: JSON.stringify({ dailyLimit: enforceHit.entry.daily_limit ?? DEFAULT_SHARED_DAILY, perSecondLimit: 1000, credits: creditCost }),
                }).then(r => r.json() as Promise<{ success: boolean; limitType?: string }>);
                const refuse = !verdict.success && verdict.limitType !== 'per_second';
                if (refuse) markEnforceSpent(bucket, Date.now());
                const refusal = enforceDecision(refuse);
                if (refusal) return refusal;
            } catch (error) {
                reportError(error, { site: "enforce_budget_do" });
            }
        }

        // Route content.openalex.org/* OR /content/* to content worker
        const isContentRequest = url.hostname === 'content.openalex.org' || /^\/content(\/|$)/i.test(url.pathname);
        // /query/text goes to the query writer Worker, through this same block: one entry credit at /check, then
        // settled to the X-Credits-Cost it reports (oxjob #1494).
        const isQueryText = classification.type === 'query_text';

        if (isContentRequest || isQueryText) {
            let contentResponse: Response;
            if (isQueryText) {
                if (!env.QUERY_WRITER) {
                    contentResponse = new Response(JSON.stringify({ error: "Writing queries from plain words isn't available on this server yet." }),
                        { status: 503, headers: { "Content-Type": "application/json", "X-Credits-Cost": "0" } });
                } else {
                    try {
                        contentResponse = await env.QUERY_WRITER.fetch(new Request(req.url, req));
                    } catch (error) {
                        console.error("Query writer call failed:", error);
                        reportError(error, { site: "query_writer" });
                        contentResponse = new Response(JSON.stringify({ error: "The query writer failed; nothing was charged. Try again in a moment." }),
                            { status: 502, headers: { "Content-Type": "application/json", "X-Credits-Cost": "0" } });
                    }
                }
            } else {
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

            contentResponse = await env.CONTENT_WORKER.fetch(contentReq);
            }

            // Query text settles in both directions to the query writer's price (settleCredits: /charge past the entry
            // credit, /refund below it; errors are free). An overrun past the caller's balance lands on the daily
            // counter, never on prepaid: we absorb it (Jason, 2026-10-11, oxjob #1494).
            // Content: check if the worker returned a different credit cost (e.g., 1 for 404) and refund.
            const actualCostHeader = contentResponse.headers.get("X-Credits-Cost");
            const actualCost = isQueryText
                ? actualCreditCost(contentResponse.status, creditCost, actualCostHeader)
                : (actualCostHeader ? parseInt(actualCostHeader, 10) : creditCost);
            let adjustedRemaining = rateLimitResult.remaining ?? 0;

            // Refund credits if actual cost < charged cost
            let adjustedOnetimeRemaining = rateLimitResult.onetimeRemaining ?? 0;
            if (isQueryText) {
                ({ remaining: adjustedRemaining, onetimeRemaining: adjustedOnetimeRemaining } = await settleCredits(limiter, {
                    charged: creditCost, actual: actualCost, dailyLimit: limit, onetimeBalance: onetimeCreditsBalance,
                    remaining: adjustedRemaining, onetimeRemaining: adjustedOnetimeRemaining,
                }));
            } else if (actualCost < creditCost) {
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
                    reportError(error, { site: "refund_credits" });
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
                creditCost: actualCost,
                trustedUi
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
            "X-Cost-USD": creditsToUsd(creditCost).toString(),
            // What the caller has left after the up-front charge, so an origin pricing a
            // query from its plan can refuse one that won't fit before running it (oxjob #1533)
            [CREDITS_REMAINING_HEADER]: creditsRemainingForOrigin(rateLimitResult.remaining, rateLimitResult.onetimeRemaining).toString()
        });
        if (isGrandfathered) proxyHeaders.set(GRANDFATHERED_HEADER, "1");
        if (trustedUi) proxyHeaders.set(WEBSITE_HEADER, "1");

        // Only add Content-Type for POST requests
        if (req.method === "POST") {
            proxyHeaders.set("Content-Type", req.headers.get("Content-Type") || "application/json");
        }

        // Forward the caller's key so elastic-api can relay it to users-api for
        // collection resolution (oxjob #228 QA-040), whether it came as a Bearer
        // header or as ?api_key= (#283, oxjob #1505). Proxy has already validated
        // the key above; users-api re-validates by lookup.
        const forwardedAuth = authorizationToForward(
            req.headers.get("Authorization"), apiKey, hasValidApiKey);
        if (forwardedAuth) {
            proxyHeaders.set("Authorization", forwardedAuth);
        }

        const proxyReq = new Request(openalexUrl.toString(), {
            method: req.method,
            headers: proxyHeaders,
            body: req.method === "POST" ? (rewrittenPostBody ?? await req.clone().arrayBuffer()) : undefined
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
        //
        // oxjob #521: on the normal API path, backstop the origin (which runs the 5s ES
        // query) with a 9s AbortController — set above the ES 5s soft timeout (+ API
        // overhead) so ES returns its partial first; the abort only fires on a true hang,
        // and closing the connection also cancels the upstream search on disconnect. The
        // edge-cached changefiles listing skips the signal (it must not hit the 504 path).
        const isChangefilesListing = req.method === "GET" && isChangefilesBrowse;

        // 2026-08-24 incident: /entities, /properties and /meta/entities are static
        // OQL schema metadata served by elastic-api with NO Cache-Control. Measured
        // during the incident: byte-identical across callers (no Vary, no Set-Cookie,
        // same bytes with and without Authorization), but slow — /properties is 228 KB
        // and took ~8s, /entities ~12s. The GUI fetches all three per page load, so
        // they were ~16% of api.openalex.org traffic, each holding a dyno worker for
        // seconds and starving the pool: a no-op request to `/` was taking 5.7s.
        //
        // Edge-cache them so the origin serves one per PoP per hour instead of one per
        // page load. Two details that matter:
        //   - cacheKey drops the query string. The GUI appends `mailto=`, and the
        //     response doesn't vary by caller, so without this every mailto variant
        //     would be its own entry and the hit rate would collapse.
        //   - like the changefiles listing, this skips the 9s abort (it uses 25s
        //     instead). On a cold miss a saturated origin needs longer than 9s, and a
        //     504 populates nothing — the cache would never fill and never help.
        const metadataPath = url.pathname.replace(/\/+$/, '').toLowerCase();
        const isStaticMetadata = req.method === "GET"
            && (metadataPath === '/entities' || metadataPath === '/properties' || metadataPath === '/meta/entities');

        // These are public schema documents; an inbound Authorization header would
        // make Cloudflare treat the response as private and skip the cache entirely.
        // Safe to drop: the payload is identical with and without it (verified).
        if (isStaticMetadata) {
            proxyHeaders.delete("Authorization");
        }

        // 2026-08-24 incident: the GUI's corpus-count probe, and the single largest
        // consumer of Elasticsearch CPU on the platform. `/works?per-page=1&select=id`
        // asks for ONE id, but the response carries meta.count, and an unfiltered count
        // makes ES tally all ~322M works on every call. Measured in Analytics Engine:
        // 826ms of ES time per request, 10.16M ms/hour — roughly 40% of ALL ES CPU,
        // from this one query shape.
        //
        // Caching rather than rate limiting is deliberate. The load is diffuse (every
        // front-page visitor; the heaviest single IP was 0.17% of sampled anon rows),
        // so a per-client cap can't reduce the aggregate without breaking the UI for
        // individuals — and the SPA renders a logged-out 429 as the daily-credit modal,
        // so throttling would show "you've hit today's free limit" to users who spent
        // nothing. The response is identical for every caller, so caching removes the
        // load outright and still returns the right answer. 5 min of staleness on a
        // 322M counter is immaterial.
        //
        // Narrow by construction: per-page=1 + select=id is a count probe, never a real
        // data fetch. Restricted to unauthenticated callers so private-label resolution
        // (which elastic-api derives from a forwarded Authorization header) can never
        // vary a cached body — that also covers 100% of the observed load, which is
        // entirely anonymous. Only mailto is dropped from the cache key; filter, corpus
        // and data-version all stay, so distinct probes never collide.
        //
        // Probes that name a collection (`col_…`) are never cached: their count depends
        // on the collection's members and on whether it's shared by link (oxjob #646).
        const isCountProbe = isCacheableCountProbe(
            url, req.method, !!apiKey, !!req.headers.get("Authorization"),
        );

        let countProbeCacheKey = '';
        if (isCountProbe) {
            const keyParams = new URLSearchParams();
            for (const [k, v] of [...url.searchParams.entries()].sort()) {
                if (k === 'mailto') continue;
                keyParams.append(k, v);
            }
            const qs = keyParams.toString();
            countProbeCacheKey = `${url.origin}${url.pathname}${qs ? '?' + qs : ''}`;
        }

        // 2026-08-24: briefly cut to 6000 during the incident on the theory that aborting
        // sooner would free origin capacity. Reverted — the premise was wrong. Heroku +
        // gunicorn do not abandon in-flight work when the client disconnects, so a shorter
        // abort here does NOT release the dyno worker or the ES query; that request runs on
        // until it completes or Heroku's router kills it at H12 (30s), which is why the
        // origin's p99 sat at exactly 30s while the proxy was capping itself at 6s. The
        // only effect of the shorter value was failing users sooner, so it is not worth the
        // collateral. Reclaiming origin capacity has to happen at the origin (gunicorn
        // --timeout, a server-side ES timeout) or by removing load (see the caches below).
        //
        // NB: the "cancels the upstream search on disconnect" claim in the oxjob #521 note
        // above is unverified for this stack and is what led the 6s change astray. Treat it
        // as an open question, not an established behaviour, before relying on it again.
        const ORIGIN_ABORT_MS = 9000;

        // Built as an if/else rather than a nested ternary: four cases is past the point
        // where a chained `?:` is reviewable, and this path runs on every proxied request.
        let fetchInit: RequestInit;
        if (isChangefilesListing) {
            fetchInit = { cf: { cacheTtl: 3600, cacheEverything: true } };
        } else if (isStaticMetadata) {
            fetchInit = {
                cf: { cacheTtl: 3600, cacheEverything: true, cacheKey: `${url.origin}${metadataPath}` },
                signal: AbortSignal.timeout(25000)
            };
        } else if (isCountProbe) {
            // Same 25s reasoning as the metadata paths: at 9s a cold miss 504s against a
            // saturated origin and the cache never populates, so the fix would do nothing.
            fetchInit = {
                cf: { cacheTtl: 300, cacheEverything: true, cacheKey: countProbeCacheKey },
                signal: AbortSignal.timeout(25000)
            };
        } else {
            fetchInit = { signal: AbortSignal.timeout(ORIGIN_ABORT_MS) };
        }

        let response: Response;
        try {
            response = await fetch(
                isStaticMetadata
                    ? new Request(openalexUrl.toString(), { method: req.method, headers: proxyHeaders })
                    : proxyReq,
                fetchInit
            );
        } catch (error) {
            if (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
                // Refund the credits charged at /check — the caller got no result.
                try {
                    await limiter.fetch("http://internal/refund", {
                        method: "POST",
                        body: JSON.stringify({ dailyLimit: limit, credits: creditCost, onetimeBalance: onetimeCreditsBalance })
                    });
                } catch (refundError) {
                    console.error("Failed to refund credits after gateway timeout:", refundError);
                    reportError(refundError, { site: "refund_credits_gateway_timeout" });
                }
                logAnalytics({
                    ctx, env, apiKey, req, url, scope,
                    responseTime: Date.now() - startTime,
                    statusCode: 504,
                    rateLimit: limit,
                    rateLimitRemaining: rateLimitResult.remaining ?? 0,
                    endpointType: classification.type,
                    creditCost
                });
                // oxjob #521 WS-3 Phase 0 (observe-only): a proxy-side 504 is an
                // origin hang — exactly the health signal the monitor exists for.
                observeSearchHealth(env, ctx, {
                    endpointType: classification.type,
                    ms: Date.now() - startTime,
                    status: 504,
                    anon: !apiKey
                });
                return addCorsHeaders(new Response(JSON.stringify({
                    error: "Gateway timeout",
                    message: "Your query took too long and was stopped before completing. " +
                        "This usually means a very broad search (e.g. many OR/AND/NOT terms). " +
                        "Please narrow the query and try again. You were not charged for this request.",
                    reason: "query_timeout"
                }), {
                    status: 504,
                    headers: { "Content-Type": "application/json", ...Object.fromEntries(getCorsHeaders()) }
                }));
            }
            throw error;
        }

        // Sync filters through OQL/OQO are a paid feature too (oxjob #1689; see syncGate.ts). checkProtectedParams
        // refuses them in a classic URL before any charge; OQL's date axes (#407, June 2026) assumed the engine enforced
        // the plan, which it didn't. So an armed request's answer is read as far as meta.x_query (the engine's own
        // translation: its classic URL and OQO) and refused with the same 429 when that names a sync field. The origin
        // has run the query by then, so the up-front charge is refunded: refusals are free, like every error (#863).
        if (syncGateArmed && response.status === 200 && response.body
            && (response.headers.get("Content-Type") || "").includes("application/json")) {
            const syncField = syncFieldInXQuery(await readXQuery(response.clone().body!));
            if (syncField) {
                response.body?.cancel().catch(() => {});
                await settleCredits(limiter, {
                    charged: creditCost, actual: 0, dailyLimit: limit, onetimeBalance: onetimeCreditsBalance,
                    remaining: rateLimitResult.remaining ?? 0, onetimeRemaining: rateLimitResult.onetimeRemaining ?? 0,
                });
                logAnalytics({
                    ctx, env, apiKey, req, url, scope: 'main',
                    responseTime: Date.now() - startTime,
                    statusCode: 429, rateLimit: 0, rateLimitRemaining: 0,
                    endpointType: classification.type, creditCost: 0, trustedUi,
                });
                return json(429, { error: "Plan upgrade required", message: oqlSyncMessage(syncField) });
            }
        }

        // Sampled clone for analytics body-read (oxjob #194). Must be taken
        // BEFORE response.body is consumed by the streamed `new Response(...)`
        // below — once a body stream is used, it can't be cloned. The clone
        // tees the body into two independent streams; user stream is unaffected.
        const sampledResponseForAnalytics = shouldSampleEsTook() ? response.clone() : null;

        // Settle what /check charged up front against what the request actually cost,
        // and report the settled balance in the headers so a client watching
        // X-RateLimit-Remaining sees the real number. Error responses are free (oxjob
        // #863): a 4xx/5xx gets the charge back, as on the content and 504 paths. A
        // query the origin priced from its plan (X-Credits-Cost, oxjob #1530) costs that
        // price, refunded or charged the difference either way (oxjob #1533).
        const actualCost = actualCreditCost(response.status, creditCost, response.headers.get(ORIGIN_COST_HEADER));
        const { remaining: adjustedRemaining, onetimeRemaining: adjustedOnetimeRemaining } = await settleCredits(limiter, {
            charged: creditCost,
            actual: actualCost,
            dailyLimit: limit,
            onetimeBalance: onetimeCreditsBalance,
            remaining: rateLimitResult.remaining ?? 0,
            onetimeRemaining: rateLimitResult.onetimeRemaining ?? 0
        });

        // Return response with rate limit headers
        const newHeaders = new Headers(response.headers);
        newHeaders.delete(ORIGIN_COST_HEADER); // internal: the client sees X-RateLimit-Credits-Used
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

        // Surface the 1h listing TTL to clients/downstream too, overriding the
        // origin's 4h Cache-Control (zd#8865).
        if (isChangefilesListing) {
            newHeaders.set("Cache-Control", "public, max-age=3600");
        }

        // Drop Content-Length from HEAD responses on the API path (oxjob #848).
        // The origin answers a HEAD by running the query and discarding the body,
        // so the length it reports describes *that* execution. List/search bodies
        // embed meta.db_response_time_ms (ES `took`), whose digit count moves
        // between runs, so the next GET is routinely 1-2 bytes off — two GETs of
        // the same URL disagree with each other too. Clients that treat the URL as
        // a file (DuckDB httpfs `read_json`, some crawlers) HEAD for a size, then
        // assert the GET matches it, and fail: zd#23471 / GH OpenAlex#14.
        //
        // We can't honour that contract anyway — the API ignores Range and returns
        // 200 + the whole body — so promising a length is the bug, not the drift.
        // Omitting it makes those clients fall back to a plain full download (the
        // `SET force_download=true` workaround, but automatic). Verified under
        // workerd against a mock origin that reproduces the drift: DuckDB went
        // 33/40 -> 40/40 passing, and origin GETs per read_json fell ~4x (the
        // failing path silently retries the GET several times before erroring).
        // Scoped to HEAD on this path only; the content API (early-returned
        // above) serves static R2 objects where a promised length is real.
        if (req.method === "HEAD") {
            newHeaders.delete("Content-Length");
        }

        // A keyless 200 JSON answer carries meta.notice about keys (oxjob #1686; see keylessNotice.ts). Spliced into
        // the stream, so the length changes: drop Content-Length.
        let responseBody = response.body;
        if (responseBody && wantsKeylessNotice({
            method: req.method, endpointType: classification.type, status: response.status, headers: response.headers,
            apiKey, trustedUi, verifiedAssistant,
        })) {
            responseBody = responseBody.pipeThrough(metaNoticeTransform(keylessNoticeFor(url.searchParams, creditsToUsd(limit))));
            newHeaders.delete("Content-Length");
        }

        const finalResponse = addCorsHeaders(new Response(responseBody, {
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
            rateLimitRemaining: adjustedRemaining,
            endpointType: classification.type,
            creditCost: actualCost,
            trustedUi,
            responseForEsTook: sampledResponseForAnalytics
        });

        // oxjob #521 WS-3 Phase 0 (observe-only): sampled search latency/status
        // feeds the SearchHealthController state machine; singleton/list feed
        // the collateral-damage signal. Fire-and-forget — never blocks the user.
        observeSearchHealth(env, ctx, {
            endpointType: classification.type,
            ms: Date.now() - startTime,
            status: response.status,
            anon: !apiKey
        });

        return finalResponse;
    }
} satisfies ExportedHandler<Env>;

// Sentry (oxjob #1685): reports an exception that escapes the handler, then rethrows it unchanged.
export default {
    fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        return withErrorReporting({ env, waitUntil: (p) => ctx.waitUntil(p), request: req }, "fetch",
            async () => {
                const res = await handler.fetch(req, env, ctx);
                if (!uiTokenRefused.has(req)) return res;
                const out = new Response(res.body, res);  // origin responses have immutable headers
                out.headers.set(UI_TOKEN_STATUS_HEADER, "refresh");
                return out;
            });
    },
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
            activationPending: cached.activationPending,
            budgetKey: cached.budgetKey,
            cacheRefreshed: false
        };
    }

    // Cache miss — query Postgres via Hyperdrive
    let client: Client | null = null;

    try {
        client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
        await client.connect();

        // SELECT *, not a column list: activation_pending (oxjob #1697, users-api migration 106) is read when the view
        // has it, and a Worker deployed before the migration keeps working (a named missing column would throw, and
        // this lookup fails open).
        const queryResult = await client.query("SELECT * FROM api_keys_view WHERE api_key = $1", [apiKey]);

        if (queryResult.rows.length === 0) {
            await client.end();
            const result = { valid: false, error: UNKNOWN_KEY_MESSAGE };
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
            activationPending: row.activation_pending === true,
            budgetKey: typeof row.budget_key === "string" && row.budget_key ? row.budget_key : null,
            cacheRefreshed: true
        };

        await client.end();
        API_KEY_CACHE.set(apiKey, { ...result, cachedAt: now });
        return result;

    } catch (error) {
        // Fail-open: on DB errors, allow request with default rate limit
        console.error("Error checking API key via Hyperdrive:", error);
        reportError(error, { site: "api_key_check_hyperdrive" });
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
            } catch (restoreError) {
                // Best effort, but if it fails those credits are never billed.
                reportError(restoreError, { site: "onetime_writeback_restore", extra: { consumed } });
            }
            throw dbError; // reported by the catch below
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
        reportError(error, { site: "onetime_writeback" });
    }
}

function getCorsHeaders(): Headers {
    const headers = new Headers();
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, HEAD, POST, PATCH, DELETE, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Accept, Accept-Language, Accept-Encoding, Authorization, Content-Type, X-OpenAlex-UI, X-Impersonate-User");
    headers.set("Access-Control-Expose-Headers", "Cache-Control, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Onetime-Remaining, X-RateLimit-Credits-Used, X-RateLimit-Credits-Required, X-RateLimit-Reset, X-RateLimit-Limit-USD, X-RateLimit-Remaining-USD, X-RateLimit-Prepaid-Remaining-USD, X-RateLimit-Cost-USD, X-RateLimit-Cost-Required-USD, Retry-After, Location, Content-Disposition, X-OpenAlex-UI-Token");
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
                        'title_and_abstract.search',
                        'title_abstract_keywords.search'
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
// Keep in sync with plans.py in openalex-users-api. 'member-plus' is the
// Member+ org plan (users-api migration 074, 2026-08-20) that replaced
// premium-1M for ~49 orgs; omitting it here locked them out of date filters,
// changefiles and snapshot credentials.
const ENTERPRISE_PLANS = new Set([
    'premium-1M', 'premium-2M', 'premium-5M', 'premium-10M',
    'institutional', 'institutional-1M', 'institutional-2M',
    'member-plus',
    'partner',
]);

// Sync filters (filter or sort by updated/created date) are paid; the rule is shared with the OQL/OQO gate (syncGate.ts).
function checkProtectedParams(url: URL, hasValidApiKey: boolean, plan: string | null): { valid: boolean; error?: string } {
    if (plan !== null && ENTERPRISE_PLANS.has(plan)) return { valid: true };
    const hit = syncFieldInParams(url.searchParams);
    if (!hit) return { valid: true };
    return {
        valid: false,
        error: hit.kind === 'filter'
            ? `The "${hit.clause}" filter requires a Premium, Institutional, or Partner plan. See https://openalex.org/pricing for details.`
            : `Sorting by "${hit.clause}" requires a Premium, Institutional, or Partner plan. See https://openalex.org/pricing for details.`
    };
}

/** api.openalex.org/api-keys (oxjob #1697): GET explains, POST asks users-api for a key after the enforcement list. */
async function apiKeysRoute(req: Request, env: Env, ctx: ExecutionContext, startTime: number): Promise<Response> {
    const url = new URL(req.url);
    const log = (statusCode: number) => logAnalytics({
        ctx, env, apiKey: null, req, url, scope: 'api_keys',
        responseTime: Date.now() - startTime, statusCode, rateLimit: 0, rateLimitRemaining: 0, creditCost: 0,
    });
    if (req.method === "GET" || req.method === "HEAD") {
        log(200);
        return apiKeysHowResponse(req.method);
    }
    if (req.method !== "POST") {
        const resp = json(405, { error: "Method Not Allowed", code: "method_not_allowed", message: "POST a JSON body {\"email\": ...} to ask for a key; GET this URL for how." });
        resp.headers.set("Allow", "GET, HEAD, POST");
        return resp;
    }
    const body = await readApiKeysBody(req);
    if (!body) {
        log(413);
        return json(413, { error: "Payload Too Large", code: "body_too_large", message: "Send a small JSON body: {\"email\": \"your user's email address\"}." });
    }

    // oxjob #1692's enforcement list: a client whose keyless traffic it refuses can't mint keys by API either; the
    // website's sign-up (Turnstile) stays open to its people. Any enforce-mode match refuses, a shared_budget entry
    // too (on purpose: a pool sharing one keyless budget mustn't mint a key per member). Shadow records, passes.
    const hit = await matchEnforcement(await loadEnforcement(env.ENFORCEMENT, Date.now()),
        apiKeysFacts(req, body.email, refererHostOf(req.headers.get("Referer"))), Date.now());
    if (hit) {
        const refuse = hit.mode === "enforce";
        try {
            env.ENFORCE_AE?.writeDataPoint({
                indexes: [hit.entry.id],
                blobs: [hit.entry.id, hit.entry.action, hit.mode, "api_keys", refuse ? "refuse" : "pass"],
                doubles: [0],
            });
        } catch { /* analytics never blocks */ }
        if (refuse) {
            log(403);
            return json(403, { error: "Forbidden", code: "enforced", message: API_KEYS_ENFORCED_MESSAGE });
        }
    }

    // Attempts per network (IPv6 by /64), before users-api's database sees them: users-api's own caps count only
    // accounts created, so a flood of refused requests would otherwise all reach it (oxjob #1692). Fails open.
    const ip = req.headers.get("CF-Connecting-IP");
    try {
        const capped = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(`apikeys:${networkOf(ip) ?? ip ?? "anon"}`));
        const check = await capped.fetch("http://internal/check", {
            method: "POST",
            body: JSON.stringify({ dailyLimit: API_KEY_ASKS_PER_NETWORK_PER_DAY, perSecondLimit: 1, credits: 1 }),
        }).then(r => r.json() as Promise<{ success: boolean; retryAfter?: number }>);
        if (!check.success) {
            log(429);
            const tooMany = json(429, { error: "Too Many Requests", code: "rate_limit_network", message: API_KEY_ASKS_REFUSED_MESSAGE });
            tooMany.headers.set("Retry-After", String(Math.ceil(check.retryAfter ?? 3600)));
            return tooMany;
        }
    } catch (error) {
        reportError(error, { site: "api_keys_ask_limit" });
    }

    try {
        const r = await fetch(await apiKeysRequest(req, body.text, env.COLLECTION_PROXY_KEY));
        log(r.status);
        const headers = new Headers(r.headers);
        headers.set("Cache-Control", "no-store");  // the answer carries a key
        return new Response(r.body, { status: r.status, headers });
    } catch {
        log(502);
        return json(502, { error: "Bad Gateway", code: "unavailable", message: "Keys can't be requested right now. Try again in a minute, or sign up at https://openalex.org/signup." });
    }
}

function refererHostOf(referer: string | null): string | null {
    if (!referer) return null;
    try { return new URL(referer).hostname.toLowerCase(); } catch { return null; }
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
    onetimeCreditsExpiresAt?: string,
    budgetKey: string | null = null
): Promise<Response> {
    // Require a valid API key
    if (!hasValidApiKey || !apiKey) {
        return json(401, {
            error: "Authentication required",
            message: "You must provide a valid API key to check rate limit status"
        });
    }

    // Query the rate limiter DO for current status (without incrementing). An agent's key reports its account
    // key's bucket, which it spends from (oxjob #1697).
    const rateLimitKey = `credits:${budgetKey || apiKey}`;
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
        reportError(error, { site: "rate_limiter_status" });
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
    const rerankSearchCreditCost = searchCreditCost + RERANK_CREDITS;  // rerank=true, oxjob #1521

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
                search_rerank: creditsToUsd(rerankSearchCreditCost),
                rerank_extra: creditsToUsd(RERANK_CREDITS),
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
                search_rerank: rerankSearchCreditCost,
                rerank_extra: RERANK_CREDITS,
                content: 100,
                semantic: 10,
                text: 100
            }
        }
    });
}
