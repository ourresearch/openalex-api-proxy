// oxjob #521 WS-3 "SearchHealthController" — PHASE 0: OBSERVE-ONLY.
//
// One global Durable Object (idFromName(GLOBAL_HEALTH_DO_NAME)) that watches
// search health from in-band observations and simulates the GREEN/YELLOW/
// ORANGE/RED ladder from the design doc (oxjobs working/works-search-saturation/
// evidence/health-gated-anon-limiter-design.md). In Phase 0 it ENFORCES NOTHING:
//   - the Worker samples origin responses (search 1-in-5; singleton/list 1-in-50
//     as the collateral-damage signal) into 30s buckets via fire-and-forget
//     /observe calls that ride ctx.waitUntil — never on the user's latency path;
//   - the DO aggregates buckets, runs the state machine + hysteresis, and logs
//     every transition (console + an AE row, blob8='health_transition') so the
//     simulated ladder can be replayed against real incidents;
//   - GET /search-health (public, read-only) shows the live state + window.
// Enforcement (class-level anon bucket / edge degrade / auto-shed) is Phase 1+,
// gated on ≥2 clean nightly-batch calibrations (exit criteria in the design doc).
//
// Health is measured over ALL search traffic — keyed and anonymous, every
// entity — because the signal is cluster health, not anon behavior. Only the
// future enforcement is scoped to keyless non-GUI traffic.

export type HealthLevel = 0 | 1 | 2 | 3;
export const LEVEL_NAMES = ['GREEN', 'YELLOW', 'ORANGE', 'RED'] as const;

export const BUCKET_MS = 30_000;
const RING_SIZE = 10; // keep the last 5 minutes of finalized buckets

// Entry thresholds (design doc, calibrated from incident baselines: healthy
// search averages 150-240ms; 06-30 burst peaked 2.0s; 07-01 ~8s + 68% 504s).
// A bucket "qualifies for" the highest level whose bound it exceeds.
const LEVEL_BOUNDS: ReadonlyArray<{ avgMs: number; errRate: number }> = [
    { avgMs: 700, errRate: 0.02 },   // YELLOW
    { avgMs: 1500, errRate: 0.10 },  // ORANGE
    { avgMs: 3000, errRate: 0.25 },  // RED
];

// A bucket needs this many sampled search observations to carry signal; below
// that it reads as GREEN (no evidence of trouble ≈ no traffic to protect).
export const MIN_BUCKET_SAMPLES = 10;
// Escalate FAST, confirmation scaled to response severity: ONE bad bucket steps
// the state up a single level (~30-45s to first response — cheap, since the
// first rung is gentle); JUMP_CONSECUTIVE qualifying buckets jump straight to
// their common floor (a severe incident reaches RED in ~60s, via YELLOW at 30s).
export const JUMP_CONSECUTIVE = 2;
// De-escalate SLOWLY: one step down per 4 consecutive clean buckets (~2 min),
// so recovery doesn't oscillate (tighten → looks better → loosen → melt again).
export const DEESCALATE_CONSECUTIVE = 4;

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
    const err = b.errN / b.n;
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
//    the current level, step down by exactly one level.
export function nextLevel(current: HealthLevel, recentSeverities: HealthLevel[]): HealthLevel {
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
}

export class SearchHealthController implements DurableObject {
    private level: HealthLevel = 0;
    private since: number = Date.now();
    private ring: BucketStats[] = [];
    private current: BucketStats | null = null;

    constructor(
        private readonly state: DurableObjectState,
        private readonly env: { ANALYTICS?: AnalyticsEngineDataset },
    ) {
        this.state.blockConcurrencyWhile(async () => {
            try {
                const stored = await this.state.storage.get<PersistedHealth>('health');
                if (stored) {
                    this.level = stored.level;
                    this.since = stored.since;
                }
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
            if (obs.kind === 'search') {
                b.n += 1;
                b.sumMs += obs.ms;
                if (obs.status >= 500) b.errN += 1;
                if (obs.ms > 3000) b.slowN += 1;
                if (obs.anon) b.anonN += 1;
            } else {
                b.otherN += 1;
                b.otherSumMs += obs.ms;
                if (obs.status >= 500) b.otherErrN += 1;
            }
            // Piggyback the state so future enforcement phases can cache it
            // isolate-side from the same call (design doc §state propagation).
            return Response.json({ ok: true, state: LEVEL_NAMES[this.level] });
        }

        if (url.pathname === '/state' && request.method === 'GET') {
            await this.rollBuckets(now);
            return Response.json({
                phase: 'observe-only',
                state: LEVEL_NAMES[this.level],
                since: new Date(this.since).toISOString(),
                enforcing: false,
                window: this.ring.map(summarize),
                currentBucket: this.current ? summarize(this.current) : null,
            });
        }

        return Response.json({ ok: false, error: 'not found' }, { status: 404 });
    }

    // Alarm keeps the ladder moving when traffic goes quiet (e.g. RED with the
    // flood gone: silent buckets read GREEN and walk the state back down).
    async alarm(): Promise<void> {
        await this.rollBuckets(Date.now());
    }

    private async rollBuckets(now: number): Promise<void> {
        const bucketStart = Math.floor(now / BUCKET_MS) * BUCKET_MS;
        if (!this.current) {
            this.current = newBucket(bucketStart);
            await this.state.storage.setAlarm(bucketStart + BUCKET_MS + 1000);
            return;
        }
        if (this.current.start === bucketStart) return;

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
        const next = nextLevel(this.level, severities);
        if (next === this.level) return;

        const from = this.level;
        this.level = next;
        this.since = Date.now();
        try {
            await this.state.storage.put('health', { level: this.level, since: this.since } satisfies PersistedHealth);
        } catch { /* observe-only: a lost persist just means amnesia on restart */ }

        const last = this.ring[this.ring.length - 1];
        const avg = last && last.n ? Math.round(last.sumMs / last.n) : 0;
        const errPct = last && last.n ? Math.round((last.errN / last.n) * 10000) / 100 : 0;
        console.log(JSON.stringify({
            event: 'search_health_transition',
            phase: 'observe-only',
            from: LEVEL_NAMES[from],
            to: LEVEL_NAMES[next],
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

// Worker-side hook. Fire-and-forget on ctx.waitUntil: the observation happens
// after the response is already streaming and a DO failure can never affect a
// request (Phase 0 hard invariant: this file changes no request outcomes).
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
            await stub.fetch('http://internal/observe', {
                method: 'POST',
                body: JSON.stringify({ ms: obs.ms, status: obs.status, kind, anon: obs.anon } satisfies HealthObservation),
            });
        } catch { /* observe-only: swallow everything */ }
    })());
}
