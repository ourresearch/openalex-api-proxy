// A higher per-second cap for named accounts (oxjob #1689).
//
// Every key's per-second cap follows its daily credits (50/30/10 a second; see the call site in index.ts). openalex.org
// now renders record pages on the server, all with one service key, and crawlers fetch them in bursts (Googlebot alone
// ~1M pages a day with 3x peaks, plus Bing and AI crawlers), so that one key outruns 50/s and the refused renders fall
// back to an empty page shell. HIGH_RPS_ACCOUNTS lists accounts (user or org ids, comma-separated, like
// QUERY_TEXT_ACCOUNTS) whose keys get their own cap: `user-abc` = DEFAULT_HIGH_RPS a second, `user-abc:800` = 800.
// Daily credits are unchanged. Only a valid key's own account is matched (a user key carries no org id), so keyless
// traffic, Origin/Referer and UI tokens never get it. A malformed entry is skipped: that account keeps its tier.

export const DEFAULT_HIGH_RPS = 500;
// Ceiling: a key's bucket is one Durable Object, which Cloudflare soft-limits at about 1,000 requests a second (past
// that its calls fail, and the proxy fails open). A cap above this needs the bucket sharded first.
export const MAX_HIGH_RPS = 1000;

export function parseHighRpsAccounts(raw: string | undefined): Map<string, number> {
    const caps = new Map<string, number>();
    for (const entry of (raw ?? "").split(",")) {
        const [id, rps, ...extra] = entry.split(":").map((s) => s.trim());
        if (!id || extra.length) continue;
        const cap = rps === undefined ? DEFAULT_HIGH_RPS : Number(rps);
        if (!Number.isInteger(cap) || cap < 1) continue;
        caps.set(id, Math.min(cap, MAX_HIGH_RPS));
    }
    return caps;
}

// Parsed once per isolate; the var only changes with a deploy.
let parsed: { raw: string | undefined; caps: Map<string, number> } | null = null;

/** The per-second cap for a request: the key's account's own cap if HIGH_RPS_ACCOUNTS lists it, else the tier. */
export function perSecondLimitFor(maxCreditsPerDay: number, keyAccountIds: string[], highRpsAccounts: string | undefined): number {
    if (!parsed || parsed.raw !== highRpsAccounts) parsed = { raw: highRpsAccounts, caps: parseHighRpsAccounts(highRpsAccounts) };
    for (const id of keyAccountIds) {
        const cap = parsed.caps.get(id);
        if (cap !== undefined) return cap;
    }
    return maxCreditsPerDay > 10000 ? 50 : (maxCreditsPerDay > 1000 ? 30 : 10);
}
