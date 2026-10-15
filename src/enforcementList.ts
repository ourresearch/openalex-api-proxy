// A private enforcement list for keyless traffic (oxjob #1692, Jason 2026-10-15).
//
// This file is the whole public mechanism: the list itself, and how entries get on it, are private. Each entry names
// one client signature (an exact user agent, a contact address, a referring site, a network prefix, an ASN, or a
// combination; strings that could identify a person are stored as hashes) and one action:
//   shared_budget: every keyless request matching the entry shares one daily budget, across all its IPs.
//   block:         keyless requests matching the entry are refused.
// Entries expire. Keys, the website (trustedUi) and verified AI assistants are never matched: the caller checks that.
//
// Modes, from one KV key ("state"): off (ignore the list), shadow (record what each entry would refuse, change
// nothing), enforce (act). An entry marked mode "shadow" stays in shadow while the list enforces, to trial it.
// Shadow and enforce run the same code, down to the budget counting; only the final refusal differs.
//
// Cost: the list is read from KV at most once a minute per isolate and matched in memory; user agents and contact
// addresses are hashed only when some entry needs them. Fails open: no KV, a bad read or a bad entry means no action.

import { sha256Hex } from "./contactBudget";
import { networkOf } from "./uiToken";

export type EnforceMode = "off" | "shadow" | "enforce";
export interface EnforceMatch {
    ua_sha?: string;        // sha256Hex of the exact User-Agent
    mailto_sha?: string;    // sha256Hex of the lowercased, trimmed mailto
    referer_host?: string;  // exact Referer host, lowercase
    ip_prefix?: string;     // IPv4 dotted prefix ending in "." ("203.0.113.")
    net64?: string;         // IPv6 /64 as networkOf() writes it ("2001:db8:abcd:12::/64")
    asn?: number;           // Cloudflare request.cf.asn
}
export interface EnforceEntry {
    id: string;
    match: EnforceMatch;
    action: "shared_budget" | "block";
    daily_limit?: number;   // shared_budget credits per day (default one keyless IP's 1,000)
    expires: number;        // epoch seconds
    mode?: "shadow";
}
export interface EnforceState { mode: EnforceMode; entries: EnforceEntry[] }
export interface RequestFacts { ua: string; mailto: string | null; refererHost: string | null; ip: string | null; asn: number | null }
export interface EnforceHit { entry: EnforceEntry; mode: "shadow" | "enforce" }

export const OFF: EnforceState = { mode: "off", entries: [] };
export const DEFAULT_SHARED_DAILY = 1_000;
const MAX_ENTRIES = 500;
const REFRESH_MS = 60_000;

const HEX32 = /^[0-9a-f]{32}$/;

function cleanEntry(e: unknown): EnforceEntry | null {
    if (!e || typeof e !== "object") return null;
    const x = e as Record<string, unknown>;
    const m = (x.match && typeof x.match === "object" ? x.match : {}) as Record<string, unknown>;
    const match: EnforceMatch = {};
    if (typeof m.ua_sha === "string" && HEX32.test(m.ua_sha)) match.ua_sha = m.ua_sha;
    if (typeof m.mailto_sha === "string" && HEX32.test(m.mailto_sha)) match.mailto_sha = m.mailto_sha;
    if (typeof m.referer_host === "string" && m.referer_host) match.referer_host = m.referer_host.toLowerCase();
    if (typeof m.ip_prefix === "string" && /^\d{1,3}\.(\d{1,3}\.){0,2}$/.test(m.ip_prefix)) match.ip_prefix = m.ip_prefix;
    if (typeof m.net64 === "string" && m.net64.endsWith("::/64")) match.net64 = m.net64;
    if (typeof m.asn === "number" && Number.isInteger(m.asn) && m.asn > 0) match.asn = m.asn;
    // Every field the entry named must have survived, and it must name at least one: a half-read entry matches nothing.
    if (Object.keys(match).length === 0 || Object.keys(match).length !== Object.keys(m).length) return null;
    if (typeof x.id !== "string" || !/^[\w.-]{1,40}$/.test(x.id)) return null;
    if (x.action !== "shared_budget" && x.action !== "block") return null;
    if (typeof x.expires !== "number") return null;
    const daily = typeof x.daily_limit === "number" && x.daily_limit > 0 ? Math.floor(x.daily_limit) : undefined;
    return { id: x.id, match, action: x.action, expires: x.expires, ...(daily ? { daily_limit: daily } : {}),
             ...(x.mode === "shadow" ? { mode: "shadow" as const } : {}) };
}

export function parseState(raw: unknown): EnforceState {
    if (!raw || typeof raw !== "object") return OFF;
    const r = raw as Record<string, unknown>;
    const mode: EnforceMode = r.mode === "shadow" || r.mode === "enforce" ? r.mode : "off";
    const entries = Array.isArray(r.entries) ? r.entries.slice(0, MAX_ENTRIES).map(cleanEntry).filter((e): e is EnforceEntry => e !== null) : [];
    return { mode, entries };
}

let cached: { state: EnforceState; at: number } | null = null;

export async function loadEnforcement(kv: KVNamespace | undefined, nowMs: number): Promise<EnforceState> {
    if (!kv) return OFF;
    if (cached && nowMs - cached.at < REFRESH_MS) return cached.state;
    try {
        cached = { state: parseState(await kv.get("state", { type: "json", cacheTtl: 60 })), at: nowMs };
    } catch {
        cached = { state: cached?.state ?? OFF, at: nowMs };  // keep the last good list through a KV blip
    }
    return cached.state;
}

/** The first live entry this keyless request matches (blocks before shared budgets), or null. */
export async function matchEnforcement(state: EnforceState, f: RequestFacts, nowMs: number): Promise<EnforceHit | null> {
    if (state.mode === "off" || state.entries.length === 0) return null;
    const now = nowMs / 1000;
    let uaSha: string | undefined, mailSha: string | undefined, net: string | null | undefined;
    const live = state.entries.filter(e => e.expires > now).sort((a, b) => (a.action === "block" ? 0 : 1) - (b.action === "block" ? 0 : 1));
    for (const e of live) {
        const m = e.match;
        if (m.asn !== undefined && m.asn !== f.asn) continue;
        if (m.referer_host !== undefined && m.referer_host !== f.refererHost) continue;
        if (m.ip_prefix !== undefined && !(f.ip && !f.ip.includes(":") && f.ip.startsWith(m.ip_prefix))) continue;
        if (m.net64 !== undefined) {
            if (net === undefined) net = f.ip && f.ip.includes(":") ? networkOf(f.ip) : null;
            if (net !== m.net64) continue;
        }
        if (m.ua_sha !== undefined) {
            if (uaSha === undefined) uaSha = await sha256Hex(f.ua);
            if (uaSha !== m.ua_sha) continue;
        }
        if (m.mailto_sha !== undefined) {
            if (!f.mailto) continue;
            if (mailSha === undefined) mailSha = await sha256Hex(f.mailto.trim().toLowerCase());
            if (mailSha !== m.mailto_sha) continue;
        }
        return { entry: e, mode: state.mode === "enforce" && e.mode !== "shadow" ? "enforce" : "shadow" };
    }
    return null;
}

/** RateLimiter DO name for an entry's shared budget; shadow counts in its own bucket. */
export function enforceBucket(hit: EnforceHit): string {
    return `credits:enforce:${hit.mode === "shadow" ? "shadow:" : ""}${hit.entry.id}`;
}

// Shared budgets spent for the day, per isolate: bucket -> epoch ms of the next midnight UTC.
const spent = new Map<string, number>();
export function enforceSpent(bucket: string, nowMs: number): boolean {
    const until = spent.get(bucket);
    if (until === undefined) return false;
    if (nowMs < until) return true;
    spent.delete(bucket);
    return false;
}
export function markEnforceSpent(bucket: string, nowMs: number): void {
    if (spent.size > 10_000) spent.clear();
    const d = new Date(nowMs);
    spent.set(bucket, Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1));
}
export function _resetEnforcementForTests(): void { cached = null; spent.clear(); }

export const ENFORCE_BLOCK_MESSAGE = "Keyless access for this client is paused: its requests come from many networks at once, which gets around the free per-network limit. Use a free API key, which has its own budget: https://help.openalex.org/api/authentication/ (if you think this is a mistake, write to support@openalex.org).";
export const ENFORCE_BUDGET_MESSAGE = "Insufficient budget. Keyless requests from this client, across every network it uses, share one free daily budget, and it is used up (resets at midnight UTC). Use a free API key, which has its own budget: https://help.openalex.org/api/authentication/ (if you think this is a mistake, write to support@openalex.org).";
