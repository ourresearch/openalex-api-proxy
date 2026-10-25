// The origin key (oxjob #1782 side-door fix, built under #1762): a shared secret on every request the proxy sends
// to its origins (openalex-elastic-api, openalex-search-api, the text API), so the origins can tell the proxy's
// requests from direct calls to *.herokuapp.com or elastic.api.openalex.org, which skip budgets, the enforcement
// list and Cloudflare. The origins log requests without it (later they refuse them).
//
// Inert until ORIGIN_SHARED_SECRET is set (a Worker secret): unset or empty sends no header, so the proxy can deploy
// before the secret exists.

export const ORIGIN_KEY_HEADER = "X-OpenAlex-Origin-Key";

export interface OriginKeyEnv {
    OPENALEX_API_URL: string;
    SEARCH_API_URL?: string;
    TEXT_API_URL: string;
    ORIGIN_SHARED_SECRET?: string;
}

function originOf(u: string | undefined): string | null {
    if (!u) return null;
    try {
        return new URL(u).origin;
    } catch {
        return null;
    }
}

// Set the origin key on headers bound for `target`, or remove it. It goes only to a URL whose origin is one of the
// env origins, never anywhere else, and any value already on `headers` (say, copied from a client) is dropped first.
export function setOriginKey(headers: Headers, env: OriginKeyEnv, target: string | URL): void {
    headers.delete(ORIGIN_KEY_HEADER);
    const secret = (env.ORIGIN_SHARED_SECRET || "").trim();
    if (!secret) return;
    const to = originOf(String(target));
    if (!to || to === "null") return;  // an opaque origin (data:, blob:) matches nothing
    const origins = [env.OPENALEX_API_URL, env.SEARCH_API_URL, env.TEXT_API_URL].map(originOf);
    if (origins.includes(to)) headers.set(ORIGIN_KEY_HEADER, secret);
}
