import { RateLimiter } from "./rateLimiter";

export interface Env {
	openalex_db: D1Database;
	RATE_LIMITER: DurableObjectNamespace;
}

export { RateLimiter };

const OPENALEX_API_BASE = "https://api.openalex.org";

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		if (req.method !== "GET") {
			return new Response("Method Not Allowed", { status: 405 });
		}

		const url = new URL(req.url);

		// Check API key authentication (optional)
		const apiKey = getApiKeyFromRequest(req);
		let hasValidApiKey = false;

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
		}

		// Rate limiting - 50 req/sec with API key, 10 req/sec without
		const rateLimitKey = apiKey || req.headers.get("CF-Connecting-IP") || "anonymous";
		const limit = hasValidApiKey ? 50 : 10;
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
		const openalexUrl = new URL(OPENALEX_API_BASE + url.pathname);

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

		// Return the response from OpenAlex
		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers: response.headers
		});
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

async function checkApiKey(req: Request, env: Env): Promise<{valid: boolean, error?: string}> {
	const apiKey = getApiKeyFromRequest(req);

	if (!apiKey) {
		return { valid: false };
	}

	try {
		const keyExists = await env.openalex_db
			.prepare("SELECT expires_at FROM api_keys WHERE api_key = ?")
			.bind(apiKey)
			.first();

		if (!keyExists) {
			return { valid: false, error: "API key not found" };
		}

		// Check if the key has expired
		if (keyExists.expires_at) {
			const expiresAt = new Date(keyExists.expires_at as string);
			const now = new Date();
			if (expiresAt <= now) {
				return { valid: false, error: `API key expired on ${keyExists.expires_at}` };
			}
		}

		return { valid: true };

	} catch (error) {
		console.error("Error checking API key:", error);
		return { valid: false, error: "Database error" };
	}
}

/** Helpers **/
function json(status: number, data: unknown): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
	});
}
