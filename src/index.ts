import { RateLimiter } from "./rateLimiter";

export interface Env {
	openalex_db: D1Database;
	RATE_LIMITER: DurableObjectNamespace;
	OPENALEX_API_URL: string;
	EXPORTER_API_URL: string;
	TEXT_API_URL: string;
	USERS_API_URL: string;
}

export { RateLimiter };

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		// Handle OPTIONS preflight requests
		if (req.method === "OPTIONS") {
			return new Response(null, {
				status: 204,
				headers: getCorsHeaders()
			});
		}

		if (req.method !== "GET") {
			return addCorsHeaders(new Response("Method Not Allowed", { status: 405 }));
		}

		const url = new URL(req.url);

		// Check API key authentication (optional)
		const apiKey = getApiKeyFromRequest(req);
		let hasValidApiKey = false;
		let maxPerSecond = 10; // Default for unauthenticated requests

		if (apiKey) {
			const authResult = await checkApiKey(req, env);
			if (!authResult.valid) {
				const message = authResult.error || "Provide a valid API key";
				return json(401, {
					error: "Invalid or missing API key",
					message: message
				});
			}
			hasValidApiKey = true;
			maxPerSecond = authResult.maxPerSecond || 50; // Use DB value or default to 50
		}

		// Check protected parameters
		const protectedParamCheck = checkProtectedParams(url, hasValidApiKey);
		if (!protectedParamCheck.valid) {
			return json(403, {
				error: "Forbidden",
				message: protectedParamCheck.error
			});
		}

		// Determine path-specific rate limits
		const normalizedPath = url.pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
		const isTextPath = /^text\/?/.test(normalizedPath);
		const isUsersPath = /^users\/?/.test(normalizedPath);
		const isExportPath = /^export\/?/.test(normalizedPath) ||
		                     /^(?:works\/+)?[wW]\d+\.bib$/.test(normalizedPath) ||
		                     (/^works\/?/.test(normalizedPath) &&
		                      url.searchParams.get('format') &&
		                      ['csv', 'ris', 'wos-plaintext', 'zip'].includes(url.searchParams.get('format')?.trim().toLowerCase() || ''));

		// Determine rate limit based on path and authentication
		// API key increased limits ONLY apply to main OpenAlex API paths
		let limit: number;
		if (isTextPath) {
			limit = 5; // /text is always 5/sec
		} else if (isUsersPath || isExportPath) {
			limit = 10; // /users and /export always use default 10/sec, even with API keys
		} else {
			limit = maxPerSecond; // Main API uses API key limits (10 without key, DB value with key)
		}

		const rateLimitKey = apiKey || req.headers.get("CF-Connecting-IP") || "anonymous";
		const window = 1; // 1 second

		// Log rate limit check
		const ipAddress = req.headers.get("CF-Connecting-IP") || "unknown";
		console.log({
			timestamp: new Date().toISOString(),
			ip: ipAddress,
			path: url.pathname,
			hasApiKey: !!apiKey,
			apiKeyPrefix: apiKey ? apiKey.substring(0, 8) + "..." : null,
			rateLimit: limit,
			rateLimitKey: apiKey ? "API_KEY" : ipAddress
		});

		const id = env.RATE_LIMITER.idFromName(rateLimitKey);
		const stub = env.RATE_LIMITER.get(id);

		const rateLimitResponse = await stub.fetch("http://internal/check", {
			method: "POST",
			body: JSON.stringify({ key: rateLimitKey, limit, window })
		});

		const { success } = await rateLimitResponse.json<{ success: boolean }>();

		if (!success) {
			console.log({
				timestamp: new Date().toISOString(),
				ip: ipAddress,
				path: url.pathname,
				status: "RATE_LIMITED",
				limit: limit
			});

			return json(429, {
				error: "Rate limit exceeded",
				message: `You have exceeded the rate limit of ${limit} requests per second. Please try again later.`
			});
		}

		// Determine which API to use based on the request path
		const targetApiUrl = getTargetApiUrl(url, env);

		// Proxy request to the appropriate API
		const openalexUrl = new URL(targetApiUrl + url.pathname);

		// Copy all query parameters (including api_key variants)
		url.searchParams.forEach((value, key) => {
			openalexUrl.searchParams.set(key, value);
		});

		// Forward the request
		const proxyReq = new Request(openalexUrl.toString(), {
			method: req.method,
			headers: {
				"User-Agent": "OpenAlex-Proxy/1.0",
				"Accept": req.headers.get("Accept") || "application/json"
			}
		});

		const response = await fetch(proxyReq);

		// Return the response from OpenAlex with CORS headers
		return addCorsHeaders(new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers: response.headers
		}));
	}
} satisfies ExportedHandler<Env>;

/** API Key Authentication **/
function getApiKeyFromRequest(req: Request): string | null {
	// First, look for "Authorization" header (Bearer token)
	const authHeader = req.headers.get("Authorization");
	if (authHeader) {
		const parts = authHeader.split(' ');
		if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
			return parts[1];
		}
	}

	const url = new URL(req.url);

	// Then check query parameters and headers for api_key or api-key
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

	if (!apiKey) {
		return { valid: false };
	}

	try {
		const keyData = await env.openalex_db
			.prepare("SELECT expires_at, max_per_second FROM api_keys WHERE api_key = ?")
			.bind(apiKey)
			.first();

		if (!keyData) {
			return { valid: false, error: "API key not found" };
		}

		// Check if the key has expired
		if (keyData.expires_at) {
			const expiresAt = new Date(keyData.expires_at as string);
			const now = new Date();
			if (expiresAt <= now) {
				return { valid: false, error: `API key expired on ${keyData.expires_at}` };
			}
		}

		return {
			valid: true,
			maxPerSecond: keyData.max_per_second as number
		};

	} catch (error) {
		console.error("Error checking API key:", error);
		return { valid: false, error: "Database error" };
	}
}

/** CORS Helpers **/
function getCorsHeaders(): Headers {
	const headers = new Headers();
	headers.set("Access-Control-Allow-Origin", "*");
	headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH");
	headers.set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Accept-Encoding, Authorization, Cache-Control");
	headers.set("Access-Control-Expose-Headers", "Authorization, Cache-Control");
	headers.set("Access-Control-Allow-Credentials", "true");
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

/** API Routing **/
function getTargetApiUrl(url: URL, env: Env): string {
	const pathname = url.pathname;

	// Normalize the path - remove leading/trailing slashes and convert to lowercase
	const normalizedPath = pathname.replace(/^\/+|\/+$/g, '').toLowerCase();

	// Check if there are any query parameters
	const hasQueryParams = url.search.length > 0;

	// Pattern: /text routes go to text API
	if (/^text\/?/.test(normalizedPath)) {
		return env.TEXT_API_URL;
	}

	// Pattern: /users routes go to users API
	if (/^users\/?/.test(normalizedPath)) {
		return env.USERS_API_URL;
	}

	// Pattern 1: /works/W123.bib or W123.bib (no query params) -> exporter API
	// Matches: works/W123.bib, W123.bib, works/w123.bib
	if (/^(?:works\/+)?[wW]\d+\.bib$/.test(normalizedPath) && !hasQueryParams) {
		return env.EXPORTER_API_URL;
	}

	// Pattern 2: /works or /works/v2 with format=csv/ris/wos-plaintext/zip -> exporter API
	// and NO group_by or group_bys parameters
	if (/^works\/?/.test(normalizedPath)) {
		const format = url.searchParams.get('format');
		const groupBy = url.searchParams.get('group_by');
		const groupBys = url.searchParams.get('group_bys');

		if (format &&
		    ['csv', 'ris', 'wos-plaintext', 'zip'].includes(format.trim().toLowerCase()) &&
		    !groupBy &&
		    !groupBys) {
			return env.EXPORTER_API_URL;
		}
	}

	// Pattern 3: /export routes always go to exporter API
	if (/^export\/?/.test(normalizedPath)) {
		return env.EXPORTER_API_URL;
	}

	// Default: use main OpenAlex API
	return env.OPENALEX_API_URL;
}

/** Protected Parameters **/
function checkProtectedParams(url: URL, hasValidApiKey: boolean): { valid: boolean; error?: string } {
	// Check filter parameter for protected date fields
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

	// Check sort parameter for protected date fields
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

/** Helpers **/
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
