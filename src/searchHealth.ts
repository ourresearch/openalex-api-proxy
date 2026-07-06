// oxjob #521 WS-3 "SearchHealthController" — PHASE 1: HEALTH-GATED ANON BUCKET.
//
// One global Durable Object (idFromName(GLOBAL_HEALTH_DO_NAME)) that watches
// search health from in-band observations, runs the GREEN/YELLOW/ORANGE/RED
// ladder from the design doc (oxjobs working/works-search-saturation/
// evidence/health-gated-anon-limiter-design.md), and rates a SINGLE shared
// token bucket for the whole anonymous works-search class:
//   - GREEN  → no limit; the Worker's healthy fast path skips the DO entirely
//   - YELLOW → 60/s  (≈ measured typical anon demand — sheds only the surge)
//   - ORANGE → 20/s  (real rationing; 429 + free-key pitch)
//   - RED    → off   (503 + Retry-After — the old manual shed, automated)
// Sensing: the Worker samples origin responses (search 1-in-5; singleton/list
// 1-in-50 as the collateral-damage signal) into 30s buckets via fire-and-forget
// /observe calls that ride ctx.waitUntil — never on the user's latency path.
// Escalation: 1 bad bucket = +1 level (~30s); 2 consecutive jump to their
// common floor; de-escalation 1 level per 4 clean buckets (~2 min), with
// ORANGE/RED holding a 5-min minimum dwell so a clamp outlasts its cause.
// Transitions: console + AE (blob8='health_transition') + last 50 at
// GET /search-health (key-gated).
// Manual override: env FORCE_HEALTH_STATE=GREEN|YELLOW|ORANGE|RED (replaces
// the retired SHED_ANON_SEARCH flag). Failure semantics: DO unreachable →
// allow if last-known healthy, 503 if last-known ORANGE/RED (fail-closed
// exactly when it matters).
//
// Health is measured over ALL search traffic — keyed and anonymous, every
// entity — because the signal is cluster health, not anon behavior. Only the
// ENFORCEMENT is scoped to keyless, non-GUI /works search.

export type HealthLevel = 0 | 1 | 2 | 3;
export const LEVEL_NAMES = ['GREEN', 'YELLOW', 'ORANGE', 'RED'] as const;

export const BUCKET_MS = 30_000;
const RING_SIZE = 10; // keep the last 5 minutes of finalized buckets

// Entry thresholds (design doc, calibrated from incident baselines: healthy
// search averages 150-240ms; 06-30 burst peaked 2.0s; 07-01 ~8s + 68% 504s).
// A bucket "qualifies for" the highest level whose bound it exceeds.
// v3.3 (2026-07-03): YELLOW 700→850ms from day-1 live data — ~30 transitions/day
// of 700-950ms grazes vs every genuine event opening ≥1.2s (pulses 1.9-2.2s,
// midnight batch 5.4s, 09:00 burst 1.9s); healthy p99 494-631ms, so 850 still
// clears noise while delaying real detection by zero buckets.
const LEVEL_BOUNDS: ReadonlyArray<{ avgMs: number; errRate: number }> = [
    { avgMs: 850, errRate: 0.02 },   // YELLOW
    { avgMs: 1500, errRate: 0.10 },  // ORANGE
    { avgMs: 3000, errRate: 0.25 },  // RED
];

// A bucket needs this many sampled search observations to carry signal; below
// that it reads as GREEN (no evidence of trouble ≈ no traffic to protect).
export const MIN_BUCKET_SAMPLES = 10;
// The error trigger needs at least this many error samples — with ~95-sample
// buckets a 2% rate threshold alone flips on 2 sampled errors, which the
// steady ~0.3% background trips by chance. First real Phase-0 calibration
// finding (2026-07-02: GREEN→YELLOW at 388ms avg / 3 errors of 95).
export const MIN_ERR_SAMPLES = 3;
// Escalate FAST, confirmation scaled to response severity: ONE bad bucket steps
// the state up a single level (~30-45s to first response — cheap, since the
// first rung is gentle); JUMP_CONSECUTIVE qualifying buckets jump straight to
// their common floor (a severe incident reaches RED in ~60s, via YELLOW at 30s).
export const JUMP_CONSECUTIVE = 2;
// De-escalate SLOWLY: one step down per 4 consecutive clean buckets (~2 min),
// so recovery doesn't oscillate (tighten → looks better → loosen → melt again).
export const DEESCALATE_CONSECUTIVE = 4;
// v3.3: ORANGE/RED additionally hold a minimum dwell before stepping down, so
// one clamp outlasts a sustained source instead of sawtoothing (07-03 midnight
// batch: 3 clamp cycles in 8 min — the drain looks like recovery while the
// batch is still running). YELLOW is exempt: fast release at the gentle rung.
export const MIN_UNHEALTHY_DWELL_MS = 5 * 60 * 1000;
// v3.4 (2026-07-05): release-aware backoff. Two live events (07-04 15:52-16:37:
// 7 clamps/45 min incl. 3 RED entries; 07-05 08:20-08:57: 5 clamps) re-melted
// 30-90 SECONDS after each dwell expiry — buckets looked clean only BECAUSE the
// clamp was working. Re-entering ORANGE/RED within RECLAMP_WINDOW_MS of leaving
// it doubles the hold (5→10→20→30 min cap). Genuine wave events are unaffected:
// their troughs (e.g. the 07-04 10:00 grind's 17-min gaps) exceed the window,
// so the streak resets and first clamps stay at 5 min.
export const RECLAMP_WINDOW_MS = 10 * 60 * 1000;
export const MAX_UNHEALTHY_DWELL_MS = 30 * 60 * 1000;

export function effectiveDwellMs(reclampStreak: number): number {
    return Math.min(MIN_UNHEALTHY_DWELL_MS * 2 ** reclampStreak, MAX_UNHEALTHY_DWELL_MS);
}

// Worker-side sampling rates. Search drives the ladder; singleton/list is the
// collateral-damage signal the incident writeups used (cheap lookups queueing
// behind expensive search) — recorded for observation, never gating.
export const SEARCH_OBSERVE_RATE = 0.2;
export const COLLATERAL_OBSERVE_RATE = 0.02;

export const GLOBAL_HEALTH_DO_NAME = 'global:search-health-v1';

export interface BucketStats {
    start: number;      // bucket start, epoch ms (aligned to BUCKET_MS)
    n: number;          // sampled search observations
    sumMs: number;      // sum of search response times
    errN: number;       // search responses with origin status >= 500
    slowN: number;      // search responses slower than 3s
    anonN: number;      // keyless search observations (mix visibility only)
    otherN: number;     // collateral (singleton/list) observations
    otherSumMs: number;
    otherErrN: number;
}

export function newBucket(start: number): BucketStats {
    return { start, n: 0, sumMs: 0, errN: 0, slowN: 0, anonN: 0, otherN: 0, otherSumMs: 0, otherErrN: 0 };
}

export function bucketSeverity(b: BucketStats): HealthLevel {
    if (b.n < MIN_BUCKET_SAMPLES) return 0;
    const avg = b.sumMs / b.n;
    const err = b.errN >= MIN_ERR_SAMPLES ? b.errN / b.n : 0;
    let level: HealthLevel = 0;
    for (let i = 0; i < LEVEL_BOUNDS.length; i++) {
        if (avg > LEVEL_BOUNDS[i].avgMs || err > LEVEL_BOUNDS[i].errRate) {
            level = (i + 1) as HealthLevel;
        }
    }
    return level;
}

// Ladder rules:
//  - JUMP: if the last JUMP_CONSECUTIVE finalized buckets ALL qualify above the
//    current level, jump to the highest level they all qualify for (worst
//    common floor) — sustained trouble moves the state fast.
//  - STEP: a single qualifying bucket steps the state up by ONE level — fast
//    first response (~30s), and the gentle first rung absorbs the cost of a
//    one-blip false positive.
//  - DOWN: if the last DEESCALATE_CONSECUTIVE buckets are ALL strictly below
//    the current level, step down by exactly one level — EXCEPT that ORANGE/RED
//    must first have been held for dwellMs (heldMs = how long the current level
//    has been in effect; dwellMs = the backoff-scaled hold, see
//    effectiveDwellMs; escalation is never dwell-gated).
export function nextLevel(
    current: HealthLevel,
    recentSeverities: HealthLevel[],
    heldMs: number = Infinity,
    dwellMs: number = MIN_UNHEALTHY_DWELL_MS,
): HealthLevel {
    const jump = recentSeverities.slice(-JUMP_CONSECUTIVE);
    let next: HealthLevel = current;
    if (jump.length === JUMP_CONSECUTIVE) {
        const floor = Math.min(...jump) as HealthLevel;
        if (floor > next) next = floor;
    }
    const last = recentSeverities[recentSeverities.length - 1];
    if (last !== undefined && last > next) {
        next = (next + 1) as HealthLevel;
    }
    if (next > current) return next;
    if (current >= 2 && heldMs < dwellMs) return current;
    const de = recentSeverities.slice(-DEESCALATE_CONSECUTIVE);
    if (current > 0 && de.length === DEESCALATE_CONSECUTIVE && de.every((s) => s < current)) {
        return (current - 1) as HealthLevel;
    }
    return current;
}

export interface HealthObservation {
    ms: number;
    status: number;
    kind: 'search' | 'other';
    anon?: boolean;
}

// ---- Phase 1: the anon-class token bucket ------------------------------
// One bucket for ALL keyless non-GUI works search combined (10,000 IPs draw
// from the same pool as 1 — per-IP limits provably can't reach the diffuse
// swarm). Refill rate follows the health state (v3.2, calibrated from
// measured demand: anon works search ran 47-88/s daily avg pre-shed).
export const BUCKET_REFILL: Record<HealthLevel, number> = {
    0: Infinity, // GREEN: no class limit at all
    1: 60,       // YELLOW: ≈ typical demand — sheds only the surge above normal
    2: 20,       // ORANGE: ~1/3 of typical
    3: 0,        // RED: off
};

export interface AnonBucket {
    tokens: number;
    lastRefill: number;
}

// Mutates b (refill + consume). Capacity = 1 second's worth of the current
// rate, so a state change re-caps naturally on the next call.
// NOTE (review 2026-07-02): this duplicates the perSecondBucket math inline in
// rateLimiter.ts. Deliberately NOT unified in this change — touching the
// per-key limiter in the same deploy as new enforcement couples two risks.
// Follow-up: extract this tested pure helper and have RateLimiter use it.
export function checkBudget(level: HealthLevel, b: AnonBucket, now: number): { ok: boolean; retryAfter?: number } {
    const rate = BUCKET_REFILL[level];
    if (rate === Infinity) return { ok: true };
    if (rate === 0) return { ok: false, retryAfter: 60 };
    const elapsedSec = Math.max(0, (now - b.lastRefill) / 1000);
    b.tokens = Math.min(rate, b.tokens + elapsedSec * rate);
    b.lastRefill = now;
    if (b.tokens >= 1) {
        b.tokens -= 1;
        return { ok: true };
    }
    return { ok: false, retryAfter: Math.max(1, Math.ceil((1 - b.tokens) / rate)) };
}

function summarize(b: BucketStats) {
    return {
        start: new Date(b.start).toISOString(),
        severity: LEVEL_NAMES[bucketSeverity(b)],
        search: {
            n: b.n,
            avgMs: b.n ? Math.round(b.sumMs / b.n) : null,
            errRate: b.n ? Math.round((b.errN / b.n) * 1000) / 1000 : null,
            slowN: b.slowN,
            anonShare: b.n ? Math.round((b.anonN / b.n) * 100) / 100 : null,
        },
        collateral: {
            n: b.otherN,
            avgMs: b.otherN ? Math.round(b.otherSumMs / b.otherN) : null,
            errN: b.otherErrN,
        },
    };
}

interface PersistedHealth {
    level: HealthLevel;
    since: number;
    // v3.4 backoff state (older persisted records lack these; default 0)
    lastUnhealthyExit?: number;
    reclampStreak?: number;
    // v3.5 Slack episode state
    episodeOpen?: boolean;
    episodeRedAlerted?: boolean;
    episodeStartedAt?: number;
    episodePeak?: HealthLevel;
}

// Ring of recent transitions kept for GET /search-health, so spot-checking
// "when did it go YELLOW?" doesn't require an AE query. Persisted across
// DO restarts; AE remains the durable full history.
const TRANSITIONS_KEPT = 50;

interface TransitionRecord {
    at: string;                 // ISO timestamp
    from: string;               // level name
    to: string;
    trigger: {                  // the bucket stats that tipped the evaluation
        searchN: number;
        avgMs: number;
        errPct: number;
    };
}

export class SearchHealthController implements DurableObject {
    private level: HealthLevel = 0;
    private since: number = Date.now();
    private ring: BucketStats[] = [];
    private current: BucketStats | null = null;
    private transitions: TransitionRecord[] = [];
    // In-memory only: the bucket matters only while unhealthy, and a DO restart
    // refilling it costs at most 1 second of allowance.
    private anonBucket: AnonBucket = { tokens: 0, lastRefill: 0 };
    // v3.4 backoff state: when we last left ORANGE/RED, and how many times in a
    // row we've re-entered within RECLAMP_WINDOW_MS (drives effectiveDwellMs).
    private lastUnhealthyExit = 0;
    private reclampStreak = 0;
    // v3.5 Slack alerting (episode-consolidated; inert unless SLACK_WEBHOOK_URL
    // is set). An "episode" opens on a fresh entry into ORANGE/RED and closes
    // after GREEN holds for RECLAMP_WINDOW_MS — re-clamps inside the window are
    // the same episode and do NOT re-alert (sim on 5 days of history: raw
    // per-transition policy = 79 pings, consolidated = 51, of which normal
    // days are 2-11 and only genuinely-bad days are loud).
    private episodeOpen = false;
    private episodeRedAlerted = false;
    private episodeStartedAt = 0;
    private episodePeak: HealthLevel = 0;

    constructor(
        private readonly state: DurableObjectState,
        private readonly env: { ANALYTICS?: AnalyticsEngineDataset; SLACK_WEBHOOK_URL?: string },
    ) {
        this.state.blockConcurrencyWhile(async () => {
            try {
                const stored = await this.state.storage.get<PersistedHealth>('health');
                if (stored) {
                    this.level = stored.level;
                    this.since = stored.since;
                    this.lastUnhealthyExit = stored.lastUnhealthyExit ?? 0;
                    this.reclampStreak = stored.reclampStreak ?? 0;
                    this.episodeOpen = stored.episodeOpen ?? false;
                    this.episodeRedAlerted = stored.episodeRedAlerted ?? false;
                    this.episodeStartedAt = stored.episodeStartedAt ?? 0;
                    this.episodePeak = stored.episodePeak ?? 0;
                }
                const storedTransitions = await this.state.storage.get<TransitionRecord[]>('transitions');
                if (storedTransitions) this.transitions = storedTransitions;
            } catch { /* fresh start on storage error — observe-only, no harm */ }
        });
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const now = Date.now();

        if (url.pathname === '/observe' && request.method === 'POST') {
            let obs: HealthObservation;
            try {
                obs = await request.json<HealthObservation>();
            } catch {
                return Response.json({ ok: false, error: 'bad body' }, { status: 400 });
            }
            await this.rollBuckets(now);
            const b = this.current!;
            // Only 503/504 count as errors: those are the overload/timeout
            // signature (07-01: 68% 504s). Plain 500s are app bugs — a bad-query
            // retry loop must not move a load-shedding ladder (Phase-0 finding:
            // background 5xx is ~0.3% and 500-dominated, 4:1 over 504).
            const isOverloadErr = obs.status === 503 || obs.status === 504;
            if (obs.kind === 'search') {
                b.n += 1;
                b.sumMs += obs.ms;
                if (isOverloadErr) b.errN += 1;
                if (obs.ms > 3000) b.slowN += 1;
                if (obs.anon) b.anonN += 1;
            } else {
                b.otherN += 1;
                b.otherSumMs += obs.ms;
                if (isOverloadErr) b.otherErrN += 1;
            }
            // Piggyback the state so future enforcement phases can cache it
            // isolate-side from the same call (design doc §state propagation).
            return Response.json({ ok: true, state: LEVEL_NAMES[this.level] });
        }

        // Phase 1: the enforcement check. Called by the Worker for keyless
        // non-GUI works search (the healthy fast path skips this entirely).
        // Optional {force} applies a manually-pinned level (FORCE_HEALTH_STATE)
        // while still using the shared bucket for token accounting.
        if (url.pathname === '/check-anon-budget' && request.method === 'POST') {
            let force: HealthLevel | null = null;
            try {
                const body = await request.json<{ force?: string }>();
                const idx = LEVEL_NAMES.indexOf((body.force || '') as (typeof LEVEL_NAMES)[number]);
                if (idx > 0) force = idx as HealthLevel; // GREEN-force short-circuits Worker-side
            } catch { /* no body → no force */ }
            await this.rollBuckets(now);
            const level = force ?? this.level;
            const verdict = checkBudget(level, this.anonBucket, now);
            // Shape Retry-After for denials (review finding: the raw bucket math
            // yields 1s for any rate ≥ 1, which synchronizes the whole denied
            // class into 1-second retry waves against this single DO). Jittered,
            // level-scaled backoff sheds the same traffic with far less re-hit load.
            let retryAfter = verdict.retryAfter;
            if (!verdict.ok) {
                retryAfter = level === 3 ? 60
                    : level === 2 ? 30 + Math.floor(Math.random() * 11)
                    : 10 + Math.floor(Math.random() * 6);
            }
            return Response.json({
                ok: verdict.ok,
                retryAfter,
                state: LEVEL_NAMES[level],
                forced: force !== null,
            });
        }

        if (url.pathname === '/state' && request.method === 'GET') {
            await this.rollBuckets(now);
            return Response.json({
                phase: 'phase-1',
                state: LEVEL_NAMES[this.level],
                since: new Date(this.since).toISOString(),
                enforcing: true,
                ladder: { GREEN: 'no limit', YELLOW: '60/s', ORANGE: '20/s', RED: 'off (503)' },
                backoff: {
                    reclampStreak: this.reclampStreak,
                    nextUnhealthyHoldMin: effectiveDwellMs(this.reclampStreak) / 60000,
                },
                window: this.ring.map(summarize),
                currentBucket: this.current ? summarize(this.current) : null,
                recentTransitions: [...this.transitions].reverse(), // newest first
            });
        }

        return Response.json({ ok: false, error: 'not found' }, { status: 404 });
    }

    // Alarm keeps the ladder moving when traffic goes quiet (e.g. RED with the
    // flood gone: silent buckets read GREEN and walk the state back down).
    async alarm(): Promise<void> {
        await this.rollBuckets(Date.now());
    }

    // v3.5: fire-and-forget Slack ping. Inert when SLACK_WEBHOOK_URL is unset;
    // a Slack outage can never affect the ladder (waitUntil + catch + timeout).
    private sendSlack(text: string): void {
        const url = this.env.SLACK_WEBHOOK_URL;
        if (!url) return;
        this.state.waitUntil(
            fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text }),
                signal: AbortSignal.timeout(5000),
            }).catch((e) => console.error('search-health Slack ping failed:', e)),
        );
    }

    private async rollBuckets(now: number): Promise<void> {
        const bucketStart = Math.floor(now / BUCKET_MS) * BUCKET_MS;
        if (!this.current) {
            this.current = newBucket(bucketStart);
            await this.state.storage.setAlarm(bucketStart + BUCKET_MS + 1000);
            return;
        }
        if (this.current.start === bucketStart) return;

        // v3.5: close an alert episode once GREEN has held a full re-clamp
        // window — a quicker "recovered" ping would fire mid-sawtooth. RED-only
        // policy: episodes that never reached RED close silently.
        if (this.episodeOpen && this.level === 0 && now - this.since >= RECLAMP_WINDOW_MS) {
            const mins = Math.round((now - this.episodeStartedAt) / 60000);
            if (this.episodePeak === 3) {
                this.sendSlack(
                    `✅ *OpenAlex search-health: recovered* — GREEN and quiet for 10 min. ` +
                    `Episode lasted ~${mins} min, peaked RED. Anonymous search fully open.`,
                );
            }
            this.episodeOpen = false;
            this.episodeRedAlerted = false;
            this.episodePeak = 0;
            try {
                await this.state.storage.put('health', {
                    level: this.level, since: this.since,
                    lastUnhealthyExit: this.lastUnhealthyExit, reclampStreak: this.reclampStreak,
                    episodeOpen: false, episodeRedAlerted: false, episodeStartedAt: 0, episodePeak: 0,
                } satisfies PersistedHealth);
            } catch { /* non-fatal */ }
        }

        // Finalize the open bucket plus synthetic empty buckets for any silent
        // gap — no traffic means nothing to protect, which counts as healthy
        // time for de-escalation. Cap the backfill at one ring's worth.
        this.ring.push(this.current);
        let fill = 0;
        for (let s = this.current.start + BUCKET_MS; s < bucketStart && fill < RING_SIZE; s += BUCKET_MS, fill++) {
            this.ring.push(newBucket(s));
        }
        while (this.ring.length > RING_SIZE) this.ring.shift();
        this.current = newBucket(bucketStart);
        await this.evaluate();
        await this.state.storage.setAlarm(bucketStart + BUCKET_MS + 1000);
    }

    private async evaluate(): Promise<void> {
        const severities = this.ring.map(bucketSeverity);
        const now = Date.now();
        const next = nextLevel(this.level, severities, now - this.since, effectiveDwellMs(this.reclampStreak));
        if (next === this.level) return;

        const from = this.level;
        // v3.4 backoff bookkeeping: count rapid re-entries into ORANGE/RED (the
        // release-into-sustained-pressure signature); note exits so the window
        // has a reference point. Escalation WITHIN unhealthy (O→R) is neither.
        if (next >= 2 && from < 2) {
            this.reclampStreak =
                this.lastUnhealthyExit > 0 && now - this.lastUnhealthyExit < RECLAMP_WINDOW_MS
                    ? this.reclampStreak + 1
                    : 0;
        } else if (from >= 2 && next < 2) {
            this.lastUnhealthyExit = now;
        }
        this.level = next;
        this.since = now;

        // v3.5 Slack alerting — RED ONLY (Casey's call: ORANGE is routine
        // rationing, RED means anonymous search is actually paused). Episodes
        // still open on any ORANGE/RED entry so the 10-min-quiet recovery
        // consolidation works, but only the first RED of an episode pings, and
        // only RED-peaked episodes send a recovery.
        if (next >= 2 && from < 2) {
            if (!this.episodeOpen) {
                this.episodeOpen = true;
                this.episodeStartedAt = now;
                this.episodeRedAlerted = false;
                this.episodePeak = next;
            } else {
                this.episodePeak = Math.max(this.episodePeak, next) as HealthLevel;
            }
        }
        if (next === 3 && this.episodeOpen) {
            this.episodePeak = 3;
            if (!this.episodeRedAlerted) {
                this.episodeRedAlerted = true;
                const last2 = this.ring[this.ring.length - 1];
                const avg2 = last2 && last2.n ? Math.round(last2.sumMs / last2.n) : 0;
                this.sendSlack(
                    `🔴 *OpenAlex search-health: RED* — anonymous works search paused (503) while the cluster drains. ` +
                    `Trigger bucket: ${avg2}ms avg. Hold ≥ ${effectiveDwellMs(this.reclampStreak) / 60000} min. ` +
                    `Keyed clients and the GUI are unaffected.`,
                );
            }
        }

        const last = this.ring[this.ring.length - 1];
        const avg = last && last.n ? Math.round(last.sumMs / last.n) : 0;
        const errPct = last && last.n ? Math.round((last.errN / last.n) * 10000) / 100 : 0;

        this.transitions.push({
            at: new Date(this.since).toISOString(),
            from: LEVEL_NAMES[from],
            to: LEVEL_NAMES[next],
            trigger: { searchN: last?.n ?? 0, avgMs: avg, errPct },
        });
        if (this.transitions.length > TRANSITIONS_KEPT) {
            this.transitions = this.transitions.slice(-TRANSITIONS_KEPT);
        }
        try {
            await this.state.storage.put('health', {
                level: this.level,
                since: this.since,
                lastUnhealthyExit: this.lastUnhealthyExit,
                reclampStreak: this.reclampStreak,
                episodeOpen: this.episodeOpen,
                episodeRedAlerted: this.episodeRedAlerted,
                episodeStartedAt: this.episodeStartedAt,
                episodePeak: this.episodePeak,
            } satisfies PersistedHealth);
            await this.state.storage.put('transitions', this.transitions);
        } catch { /* observe-only: a lost persist just means amnesia on restart */ }
        console.log(JSON.stringify({
            event: 'search_health_transition',
            phase: 'phase-1',
            enforcing: true,
            from: LEVEL_NAMES[from],
            to: LEVEL_NAMES[next],
            reclampStreak: this.reclampStreak,
            dwellMin: next >= 2 ? effectiveDwellMs(this.reclampStreak) / 60000 : undefined,
            lastBucket: { searchN: last?.n ?? 0, avgMs: avg, errPct, collateralN: last?.otherN ?? 0 },
        }));
        try {
            // AE row so transitions are queryable next to request rows. Filter
            // with blob8='health_transition' (never a real endpoint type).
            // Doubles here do NOT follow the request-row layout: double1=last
            // bucket avg search ms, double2=err %, double3=sampled search n,
            // double4=to-level, double5=from-level.
            this.env.ANALYTICS?.writeDataPoint({
                indexes: ['health_transition'],
                blobs: ['', '', `${LEVEL_NAMES[from]}->${LEVEL_NAMES[next]}`, '', 'search-health', '', '', 'health_transition'],
                doubles: [avg, errPct, last?.n ?? 0, next, from, -1, 0],
            });
        } catch (error) {
            console.error('search_health AE write failed:', error);
        }
    }
}

// ---- Worker-side: isolate state cache ----------------------------------
// Every /observe and /check-anon-budget response piggybacks the current state;
// isolates cache it so the healthy fast path never calls the DO at all.
const STATE_CACHE_TTL_MS = 5000;
let lastKnownState: { level: HealthLevel; at: number } = { level: 0, at: 0 };

function noteState(name: string | undefined): void {
    if (!name) return;
    const idx = LEVEL_NAMES.indexOf(name as (typeof LEVEL_NAMES)[number]);
    if (idx >= 0) lastKnownState = { level: idx as HealthLevel, at: Date.now() };
}

// Worker-side hook. Fire-and-forget on ctx.waitUntil: the observation happens
// after the response is already streaming and a DO failure can never affect a
// request (hard invariant: observations change no request outcomes).
export function observeSearchHealth(
    env: { SEARCH_HEALTH: DurableObjectNamespace },
    ctx: ExecutionContext,
    obs: { endpointType: string | undefined; ms: number; status: number; anon: boolean },
): void {
    const kind: HealthObservation['kind'] | null =
        obs.endpointType === 'search' ? 'search'
        : (obs.endpointType === 'singleton' || obs.endpointType === 'list') ? 'other'
        : null;
    if (kind === null) return;
    const rate = kind === 'search' ? SEARCH_OBSERVE_RATE : COLLATERAL_OBSERVE_RATE;
    if (Math.random() >= rate) return;
    ctx.waitUntil((async () => {
        try {
            const stub = env.SEARCH_HEALTH.get(env.SEARCH_HEALTH.idFromName(GLOBAL_HEALTH_DO_NAME));
            const resp = await stub.fetch('http://internal/observe', {
                method: 'POST',
                body: JSON.stringify({ ms: obs.ms, status: obs.status, kind, anon: obs.anon } satisfies HealthObservation),
            });
            const j = await resp.json<{ state?: string }>();
            noteState(j.state);
        } catch { /* observation only: swallow everything */ }
    })());
}

export interface BudgetVerdict {
    ok: boolean;
    state: string;
    statusCode?: 429 | 503;
    retryAfter?: number;
}

// How long a cached unhealthy state may drive fail-closed decisions when the
// DO is unreachable. Bounded so a stale ORANGE/RED can't 503 an isolate's
// anon search forever after the cluster has recovered (review finding).
const FAIL_CLOSED_MAX_STALENESS_MS = 5 * 60 * 1000;
// Budget calls must fail fast into the last-known-state fallback rather than
// hang the request behind a slow DO (review finding).
const BUDGET_FETCH_TIMEOUT_MS = 1500;

// FORCE_HEALTH_STATE parsing (review finding: the old SHED_ANON_SEARCH was a
// compile-checked boolean; an env var is free text, and a silently-ignored
// typo during an incident means an operator believes the shed is armed when
// it isn't). Protective default: any unrecognized non-empty value arms RED
// and logs — mis-arming must fail toward shedding, never toward nothing.
function parseForceState(raw: string | undefined): HealthLevel | null {
    const v = (raw || '').trim().toUpperCase();
    if (v === '' || v === 'FALSE' || v === 'OFF' || v === '0' || v === 'NONE' || v === 'AUTO') return null;
    const idx = LEVEL_NAMES.indexOf(v as (typeof LEVEL_NAMES)[number]);
    if (idx >= 0) return idx as HealthLevel;
    if (v === 'TRUE' || v === 'ON' || v === '1' || v === 'SHED') return 3; // old-flag muscle memory
    console.error(`FORCE_HEALTH_STATE="${raw}" not recognized — treating as RED (protective default). ` +
        `Valid: GREEN|YELLOW|ORANGE|RED (or FALSE/OFF/AUTO for automatic).`);
    return 3;
}

// The Phase-1 enforcement check for keyless non-GUI works search.
// - FORCE_HEALTH_STATE pins the level manually (GREEN/RED short-circuit here;
//   YELLOW/ORANGE still hit the DO so token accounting stays global).
// - Cached-GREEN allows immediately at ANY age — a stale note just triggers a
//   background refresh on ctx.waitUntil. Steady state therefore adds ZERO
//   blocking DO calls (v3: no limit — and no cost — when there is no problem);
//   the escalation price is ≤1 request per isolate of lag, on top of the
//   sampled /observe piggybacks that keep active isolates current anyway.
// - Cached-RED within TTL denies locally (negative cache): a flood at RED
//   must not funnel every request into the single DO it is drowning.
// - DO error/timeout → fail by last-known state, staleness-bounded:
//   pinned YELLOW/ORANGE → deny (honor the operator's protective intent);
//   fresh ORANGE/RED → 503 (fail closed exactly when it matters);
//   unknown/stale/healthy → allow + console.error (availability, visibly).
export async function checkAnonSearchBudget(
    env: { SEARCH_HEALTH: DurableObjectNamespace; FORCE_HEALTH_STATE?: string },
    ctx: ExecutionContext,
): Promise<BudgetVerdict> {
    const forced = parseForceState(env.FORCE_HEALTH_STATE);
    if (forced === 0) return { ok: true, state: 'GREEN (forced)' };
    if (forced === 3) return { ok: false, state: 'RED (forced)', statusCode: 503, retryAfter: 60 };
    const forceParam = forced !== null ? LEVEL_NAMES[forced] : undefined;

    const now = Date.now();
    const age = now - lastKnownState.at;
    if (!forceParam && lastKnownState.level === 0) {
        if (age >= STATE_CACHE_TTL_MS) {
            // Stale GREEN: allow now, refresh off the latency path. At GREEN the
            // DO consumes no token for this, so the refresh is free.
            ctx.waitUntil(refreshStateInBackground(env));
        }
        return { ok: true, state: 'GREEN' };
    }
    if (!forceParam && lastKnownState.level === 3 && age < STATE_CACHE_TTL_MS) {
        return { ok: false, state: 'RED (cached)', statusCode: 503, retryAfter: 60 };
    }
    try {
        const stub = env.SEARCH_HEALTH.get(env.SEARCH_HEALTH.idFromName(GLOBAL_HEALTH_DO_NAME));
        const resp = await stub.fetch('http://internal/check-anon-budget', {
            method: 'POST',
            body: JSON.stringify(forceParam ? { force: forceParam } : {}),
            signal: AbortSignal.timeout(BUDGET_FETCH_TIMEOUT_MS),
        });
        const j = await resp.json<{ ok: boolean; retryAfter?: number; state: string }>();
        if (!forceParam) noteState(j.state);
        if (j.ok) return { ok: true, state: j.state };
        return {
            ok: false,
            state: j.state,
            retryAfter: j.retryAfter ?? 30,
            statusCode: j.state === 'RED' ? 503 : 429,
        };
    } catch {
        if (forceParam) {
            // The operator pinned a rationing level; without the DO we can't
            // count tokens, and silently unlimited would betray the pin.
            return { ok: false, state: `${forceParam} (forced, DO error)`, statusCode: 429, retryAfter: 15 };
        }
        if (lastKnownState.level >= 2 && age < FAIL_CLOSED_MAX_STALENESS_MS) {
            return { ok: false, state: 'unknown (DO error, last-known unhealthy)', statusCode: 503, retryAfter: 30 };
        }
        console.error('search-health budget check failed with no fresh unhealthy state — allowing (availability-first)');
        return { ok: true, state: 'unknown (DO error)' };
    }
}

async function refreshStateInBackground(env: { SEARCH_HEALTH: DurableObjectNamespace }): Promise<void> {
    try {
        const stub = env.SEARCH_HEALTH.get(env.SEARCH_HEALTH.idFromName(GLOBAL_HEALTH_DO_NAME));
        const resp = await stub.fetch('http://internal/check-anon-budget', {
            method: 'POST',
            body: '{}',
            signal: AbortSignal.timeout(BUDGET_FETCH_TIMEOUT_MS),
        });
        const j = await resp.json<{ state?: string }>();
        noteState(j.state);
    } catch { /* background refresh only — next request or observe will retry */ }
}
