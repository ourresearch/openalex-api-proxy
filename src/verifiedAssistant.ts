// Verified AI assistants get their own keyless budget (oxjob #1686).
//
// Claude's web fetch (all of claude.ai), ChatGPT, Mistral and Perplexity fetch for a person from a few shared IPs.
// On the 1,000-credit keyless budget per IP, claude.ai's one IP ran dry about 3 minutes after midnight UTC and got
// ~49K 429s a day; 99% of its 234K searches in the week of 5 Oct 2026 failed. Verified assistants now get
// 5,000,000 credits ($500) a day per IP, in a rate-limit bucket of their own (so the per-second cap derived from it
// is 50/s). Jason, 2026-10-14: fund every assistant well, so people get used to asking OpenAlex. Serving all of
// claude.ai's refused demand that day was ~0.3% of ES CPU; the cap allows ~14x that before anything is refused. Everything else about them stays keyless: the anon-search ladder, the keyless cursor rule, the
// search-length gate and the anonymous boolean throttle all still apply.
//
// How the Worker knows, without trusting the client: a Cloudflare Transform Rule (phase http_request_late_transform)
// on api.openalex.org sets VERIFIED_ASSISTANT_HEADER to the Worker secret VERIFIED_ASSISTANT_TOKEN when Cloudflare
// has verified the bot as an AI assistant (cf.verified_bot_category eq "AI Assistant"), excluding Cloudflare's own
// network (ASN 13335), whose "AI Assistant" traffic is a platform any customer can drive. The rule overwrites a client-sent header when it matches; when it doesn't match, a
// client-sent header passes through, so the value must equal the secret. Secret unset = feature off.

import { timingSafeEqual } from "./uiToken";

export const VERIFIED_ASSISTANT_HEADER = "X-OpenAlex-Verified-Assistant";
export const VERIFIED_ASSISTANT_CREDITS_PER_DAY = 5_000_000;

export function isVerifiedAssistant(apiKey: string | null, presented: string | null, secret: string | undefined): boolean {
    // A key always wins: the caller is on its own budget, never the assistant one.
    if (apiKey || !secret || !presented) return false;
    return timingSafeEqual(presented, secret);
}
