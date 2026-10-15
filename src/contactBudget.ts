// One keyless budget per contact address (oxjob #1692, Jason 2026-10-15).
//
// A keyless caller who sends `mailto=` names itself. Every keyless request that names the same address shares one
// daily budget across all the IPs it comes from, on top of each IP's own budget: a real-looking address gets a
// free key's day (10,000 credits, $1), a placeholder (example.org, you@...) one keyless IP's day (1,000). On
// 14-15 Oct, 221 placeholder addresses and 39 real-looking ones were each spread over 20+ IPs and together took
// 5.4M credits a day keyless (16.7% of keyless credits), far past what one person or company gets.
//
// Not for: keyed requests (their key is the identity), the website (trustedUi), verified AI assistants, and
// openalex.org addresses (the website and our own tools send them; spoofers of ui@openalex.org are just keyless).
//
// Cost: one extra Durable Object call per keyless request with a mailto that passed its IP's budget. Once an
// address's day is spent, this isolate refuses it without any DO call until midnight UTC, so a pool's flood never
// reaches the DO. The DO name holds a hash, never the address.

export const CONTACT_DAILY_CREDITS = 10_000;          // a free key's day
export const PLACEHOLDER_DAILY_CREDITS = 1_000;       // one keyless IP's day
export const CONTACT_PER_SECOND = 50;

const PLACEHOLDER = /@example\.(org|com|net)$|^(you|your|user|test|email|name|me)@/;

export interface ContactBudget {
    bucket: string;       // RateLimiter DO name
    dailyLimit: number;
    placeholder: boolean;
}

async function sha256Hex(s: string): Promise<string> {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
    return Array.from(d.slice(0, 16), b => b.toString(16).padStart(2, "0")).join("");
}

/** The shared budget a keyless request's contact address falls under, or null when none applies. */
export async function contactBudgetFor(searchParams: URLSearchParams, who: {
    apiKey: string | null;
    trustedUi: boolean;
    verifiedAssistant: boolean;
}): Promise<ContactBudget | null> {
    if (who.apiKey || who.trustedUi || who.verifiedAssistant) return null;
    const addr = (searchParams.get("mailto") || "").trim().toLowerCase();
    const at = addr.lastIndexOf("@");
    if (at < 1 || at === addr.length - 1) return null;  // not an address: nothing to share
    if (addr.endsWith("@openalex.org")) return null;
    const placeholder = PLACEHOLDER.test(addr);
    return {
        bucket: `credits:contact:${await sha256Hex(addr)}`,
        dailyLimit: placeholder ? PLACEHOLDER_DAILY_CREDITS : CONTACT_DAILY_CREDITS,
        placeholder,
    };
}

// Addresses whose day is spent, per isolate: bucket -> epoch ms of the next midnight UTC.
const spent = new Map<string, number>();

export function contactSpent(bucket: string, nowMs: number): boolean {
    const until = spent.get(bucket);
    if (until === undefined) return false;
    if (nowMs < until) return true;
    spent.delete(bucket);
    return false;
}

export function markContactSpent(bucket: string, nowMs: number): void {
    if (spent.size > 10_000) spent.clear();  // shortcut: crude bound; a pool rotating addresses only costs DO calls
    const d = new Date(nowMs);
    spent.set(bucket, Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1));
}

/** Test hook. */
export function _resetContactSpent(): void { spent.clear(); }

export function contactBudgetMessage(c: ContactBudget): string {
    return c.placeholder
        ? "Insufficient budget. This request has no API key and its mailto is a placeholder address, which requests from many networks share; together they have used that address's free daily budget (resets at midnight UTC). Get a free key with its own $1/day: https://help.openalex.org/api/authentication/ then add api_key=YOUR_KEY to your requests."
        : "Insufficient budget. This request has no API key, and keyless requests naming this mailto address, from every network that sends it, have used its free daily budget ($1.00, the same as a free key; resets at midnight UTC). Get a free key with its own budget: https://help.openalex.org/api/authentication/ then add api_key=YOUR_KEY to your requests.";
}
