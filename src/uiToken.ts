// UI-provenance token (oxjob #338, Phase 5a / "P-A").
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
// HARD INVARIANT: this token is PROVENANCE, never AUTHORIZATION. A missing,
// expired, or forged token must NEVER block, throttle, or downgrade an API
// request — it only flips an analytics flag. The OpenAlex API stays wide open.
//
// Honest limitation (see work/phase5a-turnstile-design.md in oxjobs #338):
// Turnstile is the same defense class as the Managed Challenge that the
// AS132203 headless fleet already defeats, so this does not hard-stop
// sophisticated bots from minting tokens. It kills the trivial string-copy
// spoof and yields a far cleaner analytics signal; the ES-cost lever is #340.

const TOKEN_VERSION = 1;
const TURNSTILE_SITEVERIFY_URL =
    "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export interface UiTokenPayload {
    v: number;      // token version
    iat: number;    // issued-at (epoch seconds)
    exp: number;    // expiry (epoch seconds)
    nonce: string;  // random, makes each token unique (no replay value on its own)
}

export interface VerifyResult {
    valid: boolean;
    reason?: "malformed" | "bad_signature" | "expired" | "bad_version" | "no_secret";
    payload?: UiTokenPayload;
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

// Constant-time compare so signature checks don't leak via timing.
function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

// ---- mint / verify ---------------------------------------------------------

/**
 * Mint a signed UI-provenance token. `nonce` defaults to a fresh random value;
 * pass one only in tests for determinism.
 */
export async function mintUiToken(
    secret: string,
    nowMs: number,
    ttlSeconds: number,
    nonce: string = crypto.randomUUID(),
): Promise<string> {
    const iat = Math.floor(nowMs / 1000);
    const payload: UiTokenPayload = { v: TOKEN_VERSION, iat, exp: iat + ttlSeconds, nonce };
    const body = encodeJson(payload);
    const sig = bytesToB64url(await hmac(secret, body));
    return `${body}.${sig}`;
}

/**
 * Verify a UI-provenance token. Never throws — returns {valid:false, reason}
 * on any problem so callers can treat every failure as simply "untrusted".
 */
export async function verifyUiToken(
    token: string | null | undefined,
    secret: string | undefined,
    nowMs: number,
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
    if (payload.v !== TOKEN_VERSION) return { valid: false, reason: "bad_version" };
    if (typeof payload.exp !== "number" || payload.exp * 1000 <= nowMs) {
        return { valid: false, reason: "expired" };
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
        const data = (await resp.json()) as { success?: boolean; "error-codes"?: string[] };
        return { success: data.success === true, errorCodes: data["error-codes"] };
    } catch {
        return { success: false, errorCodes: ["verify-failed"] };
    }
}
