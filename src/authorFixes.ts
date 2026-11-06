// Author fixes (oxjob #1430): /authors/{id}/fixes[/{fix}] and /authors/{id}/fix_estimate, plus /fixes, /fixes/estimate and /fixes/queue
// (oxjob #2055), are served by the openalex-author-fixes Heroku app (the Profile Doctor). Since 2026-11-06 any API key may run a fix, at a
// price: GETs and POSTs go through the credit limiter at 0 credits up front, and the app answers with what to settle on the caller's credits
// (X-Credits-Cost: holds and overruns; X-Credits-Refund: what comes back once a fix is priced; creditReconcile.profileFixCredits). PATCH (apply or
// revert a fix, staff only) keeps the old path past the limiter: the app checks the key itself and charges nothing.
import { setOriginKey, type OriginKeyEnv } from "./originKey";

export const AUTHOR_FIXES_PATH = /^\/authors\/(?:https?:\/\/openalex\.org\/)?[Aa]?\d+\/(?:fixes(?:\/[A-Za-z0-9]+)?|fix_estimate)\/?$/;
export const FIXES_PATH = /^\/fixes(?:\/(?:estimate|queue))?\/?$/;

export function isAuthorFixesPath(pathname: string): boolean {
    return AUTHOR_FIXES_PATH.test(pathname) || FIXES_PATH.test(pathname);
}

/** A fixes request the limiter settles (GET, HEAD, POST); PATCH and anything else take the uncharged path. */
export function isBilledFixesRequest(pathname: string, method: string): boolean {
    return isAuthorFixesPath(pathname) && ["GET", "HEAD", "POST"].includes(method.toUpperCase());
}

export interface AuthorFixesForward {
    authorization: string | null;   // authorizationToForward(): a ?api_key= caller's key becomes a Bearer header
    creditsRemaining?: number;      // what the caller can spend, for the app's holds (402 when a fix doesn't fit)
    env?: OriginKeyEnv & { AUTHOR_FIXES_URL?: string };   // the origin key goes only to AUTHOR_FIXES_URL
}

export async function authorFixesRequest(req: Request, originBase: string, fwd?: AuthorFixesForward): Promise<Request> {
    const url = new URL(req.url);
    url.searchParams.delete("api_key");   // the key travels as a header, never in the app's logs
    url.searchParams.delete("api-key");
    const target = new URL(url.pathname + url.search, originBase);
    const headers = new Headers();
    for (const h of ["Authorization", "Content-Type", "Accept"]) {
        const v = req.headers.get(h);
        if (v) headers.set(h, v);
    }
    if (fwd) {
        if (fwd.authorization) headers.set("Authorization", fwd.authorization);
        if (fwd.creditsRemaining !== undefined) headers.set("X-Credits-Remaining", String(Math.max(0, Math.floor(fwd.creditsRemaining))));
        if (fwd.env) setOriginKey(headers, fwd.env, target);
    }
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    return new Request(target.toString(), { method: req.method, headers, body: hasBody ? await req.arrayBuffer() : undefined });
}
