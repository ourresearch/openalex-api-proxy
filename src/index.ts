import { RateLimiter } from "./rateLimiter";

export interface Env {
	openalex_db: D1Database;
	RATE_LIMITER: DurableObjectNamespace;
	OPENALEX_API_URL: string;
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

		// Rate limiting - use max_per_second from DB for API keys, 10 req/sec without
		const rateLimitKey = apiKey || req.headers.get("CF-Connecting-IP") || "anonymous";
		const limit = maxPerSecond;
		const window = 1; // 1 second

		const id = env.RATE_LIMITER.idFromName(rateLimitKey);
		const stub = env.RATE_LIMITER.get(id);

		const rateLimitResponse = await stub.fetch("http://internal/check", {
			method: "POST",
			body: JSON.stringify({ key: rateLimitKey, limit, window })
		});

		const { success } = await rateLimitResponse.json<{ success: boolean }>();

		if (!success) {
			return json(429, {
				error: "Rate limit exceeded",
				message: `You have exceeded the rate limit of ${limit} requests per second. Please try again later.`
			});
		}

		// Proxy request to OpenAlex API
		const openalexUrl = new URL(env.OPENALEX_API_URL + url.pathname);

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
