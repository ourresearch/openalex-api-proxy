// The website token (oxjob #338 Phase 5a "UI provenance"; perks and binding below).
//
// Purpose: give the openalex.org GUI an *unforgeable* "this request came from
// the real web UI" signal, replacing the trivially-spoofable
// `mailto=ui@openalex.org` query marker. Bots copy the mailto string verbatim
// to disguise themselves as UI traffic, which poisons the UI-vs-API analytics
// split that #338 and #340 both reason about.
//
// Shape: the GUI passes a Cloudflare Turnstile solve to `POST /ui-token`; we
// verify it server-side (secret never ships to the browser) and mint a short-
// TTL HMAC token the GUI then attaches as the `X-OpenAlex-UI` header. The main
// proxy path verifies the HMAC and tags the request `trustedUi` in analytics.
//
// What the token buys (since #521, #1533, #1682): the website's perks, never
// extra budget. Website and keyless API calls share one budget per IP. The perks
// are a search facet at list price, exemption from the anonymous-search ladder,
// the long-search gate and the keyless cursor gate. A missing or rejected token
// never blocks a request; it is just priced and gated like any keyless call.
//
// Bound to the minting network (oxjob #1691/#1692, v2): a token minted on one
// IP (IPv6: one /64) is refused on any other, so one headless browser can't
// mint a token and share it across a rotating proxy pool. A refused token gets
// `X-OpenAlex-UI-Token: refresh` on the response so the website re-mints.
//
// Honest limitation (see work/phase5a-turnstile-design.md in oxjobs #338):
// Turnstile is the same defense class as the Managed Challenge that the
// AS132203 headless fleet already defeats, so a headless browser can still
// mint a token for its own IP. Binding makes that cost one solve per IP.

const TOKEN_VERSION = 2;
// v1 tokens (unbound, 30-minute TTL) still verify so open tabs keep their perks
// across the deploy; none can be minted after it. Delete after 2026-10-17.
const LEGACY_UNBOUND_VERSION = 1;
const TURNSTILE_SITEVERIFY_URL =
    "https://challenges.cloudflare.com/turnstile/v0/siteverify";
// The website's Turnstile widget is configured for openalex.org (Cloudflare widget config, read 2026-10-15),
// which covers its subdomains. A solve from anywhere else mints nothing.
export function isOpenAlexHostname(hostname: string | null | undefined): boolean {
    const h = String(hostname ?? "").toLowerCase();
    return h === "openalex.org" || h.endsWith(".openalex.org");
}

export interface UiTokenPayload {
    v: number;      // token version
    iat: number;    // issued-at (epoch seconds)
    exp: number;    // expiry (epoch seconds)
    nonce: string;  // random, makes each token unique (no replay value on its own)
    net?: string;   // v2: keyed hash of the minting network (see networkOf)
}

export interface VerifyResult {
    valid: boolean;
    reason?: "malformed" | "bad_signature" | "expired" | "bad_version" | "no_secret" | "wrong_network";
    payload?: UiTokenPayload;
}

/**
 * The network a token is bound to: an IPv4 address as is, or an IPv6 address's
 * /64 (one household or device; privacy addresses rotate inside it). Null when
 * there is no usable IP, which binds to nothing and so never verifies.
 */
export function networkOf(ip: string | null | undefined): string | null {
    if (!ip) return null;
    const s = ip.trim().toLowerCase();
    if (!s.includes(":")) return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ? s : null;
    const v4mapped = s.match(/^::ffff:(\d{1,3}(\.\d{1,3}){3})$/);
    if (v4mapped) return v4mapped[1];
    const parts = s.split("::");
    if (parts.length > 2) return null;
    const h = parts[0] ? parts[0].split(":") : [];
    const t = parts[1] ? parts[1].split(":") : [];
    const fill = parts.length === 2 ? 8 - h.length - t.length : 0;
    if (parts.length === 2 && fill < 1) return null;
    const groups = [...h, ...Array(fill).fill("0"), ...t];
    if (groups.length !== 8 || !groups.every(g => /^[0-9a-f]{1,4}$/.test(g))) return null;
    return groups.slice(0, 4).map(g => parseInt(g, 16).toString(16)).join(":") + "::/64";
}

async function networkTag(secret: string, ip: string | null | undefined): Promise<string | null> {
    const net = networkOf(ip);
    return net ? bytesToB64url(await hmac(secret, `net|${net}`)).slice(0, 16) : null;
}

// ---- base64url (no padding) over UTF-8 / bytes -----------------------------

function bytesToB64url(bytes: Uint8Array): string {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(s: string): Uint8Array {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function encodeJson(payload: UiTokenPayload): string {
    return bytesToB64url(new TextEncoder().encode(JSON.stringify(payload)));
}

// ---- HMAC-SHA256 via Web Crypto (available in the Workers runtime) ---------

async function hmac(secret: string, message: string): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
    return new Uint8Array(sig);
}

// Constant-time compare so signature checks don't leak via timing. Also used for the
// verified-assistant secret (verifiedAssistant.ts). Leaks only the length on a mismatch.
export function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

// ---- mint / verify ---------------------------------------------------------

/**
 * Mint a signed website token bound to the network of `ip` (the caller's
 * CF-Connecting-IP). `nonce` defaults to a fresh random value; pass one only in
 * tests for determinism.
 */
export async function mintUiToken(
    secret: string,
    nowMs: number,
    ttlSeconds: number,
    ip: string | null,
    nonce: string = crypto.randomUUID(),
): Promise<string> {
    const iat = Math.floor(nowMs / 1000);
    const net = await networkTag(secret, ip);
    return signPayload(secret, { v: TOKEN_VERSION, iat, exp: iat + ttlSeconds, nonce, ...(net ? { net } : {}) });
}

/** `<base64url payload>.<base64url HMAC>`: the token format every version shares. */
export async function signPayload(secret: string, payload: UiTokenPayload): Promise<string> {
    const body = encodeJson(payload);
    return `${body}.${bytesToB64url(await hmac(secret, body))}`;
}

/**
 * Verify a website token presented from `ip`. Never throws — returns
 * {valid:false, reason} on any problem so callers can treat every failure as
 * simply "untrusted".
 */
export async function verifyUiToken(
    token: string | null | undefined,
    secret: string | undefined,
    nowMs: number,
    ip: string | null,
): Promise<VerifyResult> {
    if (!secret) return { valid: false, reason: "no_secret" };
    if (!token || typeof token !== "string") return { valid: false, reason: "malformed" };

    const dot = token.indexOf(".");
    if (dot <= 0 || dot === token.length - 1) return { valid: false, reason: "malformed" };
    const body = token.slice(0, dot);
    const providedSig = token.slice(dot + 1);

    const expectedSig = bytesToB64url(await hmac(secret, body));
    if (!timingSafeEqual(providedSig, expectedSig)) return { valid: false, reason: "bad_signature" };

    let payload: UiTokenPayload;
    try {
        payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(body)));
    } catch {
        return { valid: false, reason: "malformed" };
    }
    if (payload.v !== TOKEN_VERSION && payload.v !== LEGACY_UNBOUND_VERSION) return { valid: false, reason: "bad_version" };
    if (typeof payload.exp !== "number" || payload.exp * 1000 <= nowMs) {
        return { valid: false, reason: "expired" };
    }
    if (payload.v === TOKEN_VERSION) {
        const here = payload.net ? await networkTag(secret, ip) : null;
        if (!payload.net || !here || !timingSafeEqual(payload.net, here)) return { valid: false, reason: "wrong_network", payload };
    }
    return { valid: true, payload };
}

// ---- Turnstile siteverify --------------------------------------------------

export interface TurnstileResult {
    success: boolean;
    errorCodes?: string[];
}

/**
 * Validate a Turnstile client response against Cloudflare's siteverify API.
 * `fetchImpl` is injectable for tests. Fails closed (success:false) on any
 * network/parse error — a failed verify just means "no token minted", which is
 * safe (the caller still serves API traffic; it's only the provenance mint).
 * A solve passes only if Turnstile says it was made on openalex.org or a subdomain
 * (Cloudflare's advice: check `hostname`, oxjob #1691).
 */
export async function verifyTurnstile(
    turnstileResponse: string | null | undefined,
    secret: string | undefined,
    remoteIp: string | null,
    fetchImpl: typeof fetch = fetch,
): Promise<TurnstileResult> {
    if (!secret || !turnstileResponse) return { success: false, errorCodes: ["missing-input"] };
    try {
        const form = new FormData();
        form.append("secret", secret);
        form.append("response", turnstileResponse);
        if (remoteIp) form.append("remoteip", remoteIp);
        const resp = await fetchImpl(TURNSTILE_SITEVERIFY_URL, { method: "POST", body: form });
        const data = (await resp.json()) as { success?: boolean; "error-codes"?: string[]; hostname?: string };
        if (data.success === true && !isOpenAlexHostname(data.hostname)) {
            return { success: false, errorCodes: ["hostname-mismatch"] };
        }
        return { success: data.success === true, errorCodes: data["error-codes"] };
    } catch {
        return { success: false, errorCodes: ["verify-failed"] };
    }
}
