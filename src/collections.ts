// Collections (oxjob #1515) and saved searches (#1509): api.openalex.org/collections[/...]
// and /saved-searches[/...] are served by users-api, under its /api prefix, the way
// /authors/{id}/fixes is served by the author-fixes app (authorFixes.ts). They are a
// user's own lists and searches, not entity reads: users-api checks the caller's key and
// each collection's access itself, and the proxy charges no credits.
//
// users-api reads only `Authorization: Bearer`, so a key sent as `?api_key=` (or the
// api_key header) is moved into that header and dropped from the URL. users-api limits
// logged-out reads per caller IP; from here it would see Cloudflare's egress IP, so the
// proxy names the caller's IP in a header users-api trusts only with the shared secret.
export const USERS_API_URL = "https://user.openalex.org";
export const COLLECTIONS_PATH = /^\/(?:collections|saved-searches)(?:\/.*)?$/;
export const PROXY_KEY_HEADER = "X-Collection-Proxy-Key";
export const CLIENT_IP_HEADER = "X-Collection-Client-IP";

const KEY_PARAMS = ["api_key", "api-key"];

export function isCollectionsPath(pathname: string): boolean {
    return COLLECTIONS_PATH.test(pathname);
}

function keyFrom(req: Request, url: URL): string | null {
    for (const p of KEY_PARAMS) {
        const v = url.searchParams.get(p);
        if (v) return v;
    }
    return req.headers.get("api_key") || req.headers.get("api-key");
}

export async function collectionsRequest(req: Request, originBase: string, proxyKey?: string): Promise<Request> {
    const url = new URL(req.url);
    const key = keyFrom(req, url);
    for (const p of KEY_PARAMS) url.searchParams.delete(p);
    const target = new URL("/api" + url.pathname + url.search, originBase);

    const headers = new Headers();
    // X-Impersonate-User: the website's admin "act as this user"; users-api honors it
    // only when the key belongs to an admin.
    for (const h of ["Content-Type", "Accept", "X-Impersonate-User"]) {
        const v = req.headers.get(h);
        if (v) headers.set(h, v);
    }
    const auth = req.headers.get("Authorization") || (key ? `Bearer ${key}` : null);
    if (auth) headers.set("Authorization", auth);
    const ip = req.headers.get("CF-Connecting-IP");
    if (proxyKey && ip) {
        headers.set(PROXY_KEY_HEADER, proxyKey);
        headers.set(CLIENT_IP_HEADER, ip);
    }
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    return new Request(target.toString(), { method: req.method, headers, body: hasBody ? await req.arrayBuffer() : undefined });
}
