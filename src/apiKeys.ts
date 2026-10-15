// Keys an AI agent asks for on its user's behalf (oxjob #1697): https://api.openalex.org/api-keys.
//
// POST {"email": ...} gets a working key at once ($0.10 a day, the keyless 10/s); the person clicks the link we email
// and the same key gets a free account's $1 a day. users-api does the work (views.request_api_key, its own caps and
// checks, served under /api like collections.ts): this Worker forwards the call with the caller's IP, in a header
// users-api trusts only with the shared secret, after oxjob #1692's enforcement list has had its say. GET answers
// itself, free: an agent that can only fetch URLs reads how to ask.
//
// Free: no credits, no keyless budget. A caller refused for budget must still be able to get a key.

import { collectionsRequest, USERS_API_URL } from "./collections";
import type { RequestFacts } from "./enforcementList";

export const API_KEYS_URL = "https://api.openalex.org/api-keys";
const DOCS = "https://help.openalex.org/api/authentication/#getting-a-key-for-your-user";
const SIGNUP = "https://openalex.org/signup";
const MAX_BODY_BYTES = 4096;

export function isApiKeysPath(pathname: string): boolean {
    return pathname === "/api-keys" || pathname === "/api-keys/";
}

/** One sentence the keyless notice, the keyless 429 and the root share, so they never drift apart. */
export const ASK_FOR_A_KEY = `An AI agent can get one for its user in one call: POST ${API_KEYS_URL} with {"email": "<your user's email>"}; it works at once, and we email them a link to activate it.`;

const HOW = {
    name: "Ask for a free OpenAlex API key for your user",
    method: "POST",
    url: API_KEYS_URL,
    headers: { "Content-Type": "application/json", "Idempotency-Key": "<optional: a UUID, so a retry returns the same key>" },
    body: { email: "<your user's email address: ask them, don't invent one>", name: "<optional>", agent: "<optional: what is asking, e.g. Claude Code>" },
    returns: "201 with api_key. The key works at once with $0.10 of free usage a day. We email the address a link; once they click it, the same key gets $1 a day.",
    use_the_key: "Send it as api_key=KEY on any request, or an \"Authorization: Bearer KEY\" header. Keep it in an environment variable (OPENALEX_API_KEY), not in code you share.",
    errors: {
        "400": "the address is missing, malformed, or a placeholder like you@example.com: ask your user for their real address",
        "409 account_exists": "the address already has an account and a key: your user copies it from https://openalex.org/settings/api-key",
        "409 activation_pending": "a key for the address is waiting for activation: your user clicks the link we emailed",
        "429": `too many keys from this network or email domain today: your user can sign up at ${SIGNUP} instead`,
    },
    docs: DOCS,
};
const HOW_BODY = JSON.stringify(HOW, null, 2) + "\n";

export function apiKeysHowResponse(method: string): Response {
    return new Response(method === "HEAD" ? null : HOW_BODY, {
        status: 200,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=3600",
            "X-RateLimit-Credits-Used": "0",
            "X-RateLimit-Cost-USD": "0",
        },
    });
}

/** The 429 for a key that is waiting for activation: the way out is the person's click, not a payment. */
export function pendingKeyRefusal(dailyCredits: number, dailyRemainingUsd: number): string {
    if (dailyCredits <= 0) {
        return `This key was never activated, so it has stopped working (an unactivated key works for 7 days). Ask for the activation email again: POST ${API_KEYS_URL} with the same {"email": ...}. Once your user clicks the link, this same key gets $1 a day.`;
    }
    return `Insufficient budget. This key isn't activated yet, so it has $${(dailyCredits / 10000).toFixed(2)} of free usage a day, and today's is used up ($${dailyRemainingUsd} remaining; resets at midnight UTC). Ask your user to click the link in the email titled "Activate your OpenAlex API key": the same key then gets $1 a day.`;
}

/** The 401 for a key we don't know: placeholders like YOUR_API_KEY land here, so say how to get a real one. */
export const UNKNOWN_KEY_MESSAGE = `API key not found. Get a free key at https://openalex.org/settings/api-key. ${ASK_FOR_A_KEY}`;

/** Asks per network (IPv4 address or IPv6 /64) a day, and 1 a second: a person needs one; users-api creates at
 *  most 3 accounts per network a day and turns the rest away, but only after they reach its database. */
export const API_KEY_ASKS_PER_NETWORK_PER_DAY = 10;
export const API_KEY_ASKS_REFUSED_MESSAGE = `This network has asked for keys too often today. Your user can sign up at ${SIGNUP} instead (about 30 seconds) and copy their key from https://openalex.org/settings/api-key.`;

export const API_KEYS_ENFORCED_MESSAGE = `Keys can't be requested by API for this client, because its keyless requests come from many networks at once. Your user can sign up at ${SIGNUP} (about 30 seconds) and copy their key from https://openalex.org/settings/api-key (if you think this is a mistake, write to support@openalex.org).`;

/** The request's body text (at most MAX_BODY_BYTES) and the email it names, if it parses. */
export async function readApiKeysBody(req: Request): Promise<{ text: string; email: string | null } | null> {
    const text = await req.text();
    if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) return null;
    try {
        const body = JSON.parse(text);
        const email = body && typeof body === "object" && typeof body.email === "string" ? body.email : null;
        return { text, email };
    } catch {
        return { text, email: null };
    }
}

/** The facts #1692's enforcement list matches on, with the email standing in for a keyless request's mailto. */
export function apiKeysFacts(req: Request, email: string | null, refererHost: string | null): RequestFacts {
    const cf = (req as { cf?: { asn?: unknown } }).cf;
    return {
        ua: req.headers.get("User-Agent") || "",
        mailto: email,
        refererHost,
        ip: req.headers.get("CF-Connecting-IP"),
        asn: typeof cf?.asn === "number" ? cf.asn : null,
    };
}

/** The call to users-api: collections.ts's forwarding (caller IP under the shared secret), plus the two headers
 *  users-api reads here: the User-Agent (which agents use this) and Idempotency-Key (a retry gets the same key). */
export async function apiKeysRequest(req: Request, bodyText: string, proxyKey?: string): Promise<Request> {
    const forwarded = await collectionsRequest(new Request(req.url, { method: "POST", headers: req.headers, body: bodyText }), USERS_API_URL, proxyKey);
    for (const h of ["User-Agent", "Idempotency-Key"]) {
        const v = req.headers.get(h);
        if (v) forwarded.headers.set(h, v);
    }
    forwarded.headers.set("Content-Type", "application/json");
    forwarded.headers.delete("Authorization");  // a key on this call means nothing; don't send it on
    return forwarded;
}
