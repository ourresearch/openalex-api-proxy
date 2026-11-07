import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    bucketSeverity,
    effectiveDwellMs,
    nextLevel,
    newBucket,
    checkBudget,
    MIN_BUCKET_SAMPLES,
    BUCKET_MS,
    SearchHealthController,
    type AnonBucket,
    type BucketStats,
    type HealthLevel,
} from './searchHealth';

// Build a bucket with n search observations averaging avgMs, errN of them 5xx.
function bucket(n: number, avgMs: number, errN = 0): BucketStats {
    const b = newBucket(0);
    b.n = n;
    b.sumMs = n * avgMs;
    b.errN = errN;
    return b;
}

describe('bucketSeverity', () => {
    it('reads GREEN below the sample floor no matter how slow', () => {
        expect(bucketSeverity(bucket(MIN_BUCKET_SAMPLES - 1, 9000, 5))).toBe(0);
        expect(bucketSeverity(newBucket(0))).toBe(0); // empty (silent gap) bucket
    });

    it('maps average latency to the ladder entry bounds', () => {
        expect(bucketSeverity(bucket(100, 200))).toBe(0);   // healthy baseline
        expect(bucketSeverity(bucket(100, 850))).toBe(0);   // bound is exclusive
        expect(bucketSeverity(bucket(100, 800))).toBe(0);   // v3.3: evening grazes read GREEN
        expect(bucketSeverity(bucket(100, 900))).toBe(1);   // YELLOW > 850ms
        expect(bucketSeverity(bucket(100, 2000))).toBe(2);  // ORANGE > 1.5s
        expect(bucketSeverity(bucket(100, 8000))).toBe(3);  // RED > 3s (07-01 shape)
    });

    it('maps overload-error share to the ladder independently of latency', () => {
        expect(bucketSeverity(bucket(100, 200, 1))).toBe(0);   // 1% errors
        expect(bucketSeverity(bucket(100, 200, 5))).toBe(1);   // 5% → YELLOW
        expect(bucketSeverity(bucket(100, 200, 15))).toBe(2);  // 15% → ORANGE
        expect(bucketSeverity(bucket(100, 200, 68))).toBe(3);  // 68% 504s (07-01) → RED
    });

    it('ignores the error signal below MIN_ERR_SAMPLES (small-bucket noise guard)', () => {
        // 2 errors of 20 samples = 10% rate, but 2 < MIN_ERR_SAMPLES → no trigger.
        // Phase-0 calibration finding: 3-of-95 background noise flipped YELLOW.
        expect(bucketSeverity(bucket(20, 200, 2))).toBe(0);
        expect(bucketSeverity(bucket(20, 200, 3))).toBe(2);  // 3 errors = 15% → ORANGE
    });

    it('takes the worse of latency and error signals', () => {
        expect(bucketSeverity(bucket(100, 800, 15))).toBe(2); // sub-threshold avg, ORANGE errors
    });

    it('ignores collateral (singleton/list) counters for severity', () => {
        const b = bucket(100, 200);
        b.otherN = 50;
        b.otherSumMs = 50 * 9000; // collateral very slow
        b.otherErrN = 50;
        expect(bucketSeverity(b)).toBe(0); // observation-only signal, not gating
    });
});

describe('nextLevel', () => {
    const G = 0 as HealthLevel, Y = 1 as HealthLevel, O = 2 as HealthLevel, R = 3 as HealthLevel;

    it('steps up ONE level on a single bad bucket (~30s first response)', () => {
        expect(nextLevel(G, [G, G, Y])).toBe(Y);
        expect(nextLevel(G, [G, G, R])).toBe(Y); // one blip: one gentle step, not straight to RED
        expect(nextLevel(Y, [Y, Y, O])).toBe(O);
    });

    it('escalates to the level 2 consecutive qualifying buckets agree on', () => {
        expect(nextLevel(G, [G, Y, Y])).toBe(Y);
        expect(nextLevel(Y, [Y, O, O])).toBe(O);
    });

    it('jumps straight to the worst common floor (00:00-batch shape)', () => {
        expect(nextLevel(G, [G, R, R])).toBe(R);
        expect(nextLevel(G, [Y, R])).toBe(O); // sustained ≥YELLOW + worsening last → floor+1
    });

    it('does not escalate on a mixed pair already below the current level', () => {
        expect(nextLevel(O, [R, Y])).toBe(O); // floor Y and last Y are both below O → hold
    });

    it('reaches RED from GREEN in two buckets during a severe incident', () => {
        let level: HealthLevel = G;
        level = nextLevel(level, [G, G, R]);       // first bad bucket → YELLOW (~30s)
        expect(level).toBe(Y);
        level = nextLevel(level, [G, R, R]);       // second confirms → jump to RED (~60s)
        expect(level).toBe(R);
    });

    it('de-escalates one step only after 4 consecutive clean buckets', () => {
        expect(nextLevel(R, [G, G, G, G])).toBe(O);   // one step, not straight to GREEN
        expect(nextLevel(R, [G, G, G, R])).toBe(R);   // a recent bad bucket resets the walk
        expect(nextLevel(R, [G, G, G])).toBe(R);      // needs a full window of history
        expect(nextLevel(O, [Y, Y, Y, Y])).toBe(Y);   // "clean" = strictly below current
        expect(nextLevel(Y, [G, G, G, G])).toBe(G);
    });

    it('never de-escalates below GREEN and holds steady state', () => {
        expect(nextLevel(G, [G, G, G, G])).toBe(G);
    });

    it('walks RED back to GREEN in three windows of sustained health', () => {
        let level: HealthLevel = R;
        const clean = [G, G, G, G];
        level = nextLevel(level, clean);
        level = nextLevel(level, clean);
        level = nextLevel(level, clean);
        expect(level).toBe(G);
    });

    it('v3.3 dwell: ORANGE/RED hold 5 min before stepping down, even on clean buckets', () => {
        const clean = [G, G, G, G];
        expect(nextLevel(O, clean, 60_000)).toBe(O);        // 1 min held → hold the clamp
        expect(nextLevel(R, clean, 4 * 60_000)).toBe(R);    // 4 min held → still holding
        expect(nextLevel(O, clean, 5 * 60_000)).toBe(Y);    // dwell served → release
        expect(nextLevel(R, clean, 6 * 60_000)).toBe(O);
    });

    it('v3.3 dwell: YELLOW is exempt (fast release at the gentle rung)', () => {
        expect(nextLevel(Y, [G, G, G, G], 0)).toBe(G);
    });

    it('v3.3 dwell: never gates escalation', () => {
        expect(nextLevel(O, [R, R], 0)).toBe(R);            // fresh ORANGE can still worsen
        expect(nextLevel(O, [O, O, R], 0)).toBe(R);         // single worse bucket steps up
    });
});

describe('checkBudget (anon-class token bucket)', () => {
    const G = 0 as HealthLevel, Y = 1 as HealthLevel, O = 2 as HealthLevel, R = 3 as HealthLevel;
    const fresh = (): AnonBucket => ({ tokens: 0, lastRefill: 0 });

    it('GREEN never limits and never consumes', () => {
        const b = fresh();
        for (let i = 0; i < 1000; i++) {
            expect(checkBudget(G, b, 1_000_000).ok).toBe(true);
        }
        expect(b.tokens).toBe(0); // untouched — GREEN short-circuits
    });

    it('RED always denies with Retry-After 60', () => {
        expect(checkBudget(R, fresh(), 1_000_000)).toEqual({ ok: false, retryAfter: 60 });
    });

    it('YELLOW fills to 60 tokens and denies the 61st in the same second', () => {
        const b = fresh();
        const now = 1_000_000;
        let allowed = 0;
        for (let i = 0; i < 70; i++) {
            if (checkBudget(Y, b, now).ok) allowed++;
        }
        expect(allowed).toBe(60);
        const denied = checkBudget(Y, b, now);
        expect(denied.ok).toBe(false);
        expect(denied.retryAfter).toBeGreaterThanOrEqual(1);
    });

    it('ORANGE refills at 20/s after exhaustion', () => {
        const b = fresh();
        const t0 = 1_000_000;
        while (checkBudget(O, b, t0).ok) { /* drain */ }
        // Half a second later: ~10 tokens back
        let allowed = 0;
        for (let i = 0; i < 20; i++) {
            if (checkBudget(O, b, t0 + 500).ok) allowed++;
        }
        expect(allowed).toBe(10);
    });

    it('caps accumulation at one second of rate (no burst hoarding)', () => {
        const b = fresh();
        checkBudget(Y, b, 0);              // initializes/fills
        const later = 60 * 60 * 1000;      // an hour of silence
        let allowed = 0;
        for (let i = 0; i < 200; i++) {
            if (checkBudget(Y, b, later).ok) allowed++;
        }
        expect(allowed).toBeLessThanOrEqual(60);
    });

    it('a state change re-caps naturally: ORANGE tokens carry into YELLOW refill', () => {
        const b = fresh();
        const t0 = 1_000_000;
        while (checkBudget(O, b, t0).ok) { /* drain at ORANGE */ }
        // One second later at YELLOW the bucket refills to the full 60
        let allowed = 0;
        for (let i = 0; i < 100; i++) {
            if (checkBudget(Y, b, t0 + 1000).ok) allowed++;
        }
        expect(allowed).toBe(60);
    });
});

describe('v3.4 release-aware backoff', () => {
    const G = 0 as HealthLevel, O = 2 as HealthLevel, R = 3 as HealthLevel;

    it('effectiveDwellMs doubles per rapid re-clamp and caps at 30 min', () => {
        expect(effectiveDwellMs(0)).toBe(5 * 60_000);
        expect(effectiveDwellMs(1)).toBe(10 * 60_000);
        expect(effectiveDwellMs(2)).toBe(20 * 60_000);
        expect(effectiveDwellMs(3)).toBe(30 * 60_000);   // capped
        expect(effectiveDwellMs(10)).toBe(30 * 60_000);  // stays capped
    });

    it('nextLevel honors a backed-off dwell', () => {
        const clean = [G, G, G, G];
        // 6 min held: released under the base 5-min dwell...
        expect(nextLevel(O, clean, 6 * 60_000)).toBe(1);
        // ...but HELD under a backed-off 10-min dwell (first rapid re-clamp)
        expect(nextLevel(O, clean, 6 * 60_000, effectiveDwellMs(1))).toBe(O);
        expect(nextLevel(O, clean, 11 * 60_000, effectiveDwellMs(1))).toBe(1);
        // RED with a twice-backed-off 20-min hold
        expect(nextLevel(R, clean, 19 * 60_000, effectiveDwellMs(2))).toBe(R);
        expect(nextLevel(R, clean, 21 * 60_000, effectiveDwellMs(2))).toBe(O);
    });

    it('backed-off dwell never gates escalation', () => {
        expect(nextLevel(O, [R, R], 0, effectiveDwellMs(3))).toBe(R);
    });
});

describe('v3.6 RED dwell cap', () => {
    it('RED holds cap at 10 min regardless of backoff streak', () => {
        expect(effectiveDwellMs(0, 3)).toBe(5 * 60_000);
        expect(effectiveDwellMs(1, 3)).toBe(10 * 60_000);
        expect(effectiveDwellMs(3, 3)).toBe(10 * 60_000);  // capped (was 30 for ORANGE)
        expect(effectiveDwellMs(10, 3)).toBe(10 * 60_000);
    });

    it('ORANGE keeps the full 30-min backoff ceiling', () => {
        expect(effectiveDwellMs(3, 2)).toBe(30 * 60_000);
        expect(effectiveDwellMs(3)).toBe(30 * 60_000);     // default level = ORANGE
    });
});

describe('cachedHealthLevel (oxjob #1521 rerank gate)', () => {
    it('honors FORCE_HEALTH_STATE and reads GREEN with no fresh note', async () => {
        const { cachedHealthLevel } = await import('./searchHealth');
        expect(cachedHealthLevel({ FORCE_HEALTH_STATE: 'YELLOW' })).toBe(1);
        expect(cachedHealthLevel({ FORCE_HEALTH_STATE: 'RED' })).toBe(3);
        expect(cachedHealthLevel({})).toBe(0);
    });
});

// oxjob #2088: Slack #dev hears from the ladder only when its own healing is failing. Driven through the real Durable
// Object: 10 sampled searches per 30 s bucket, then the alarm rolls the bucket (as it does every bucket in production).
describe('oxjob #2088 Slack policy: one "needs a look" per episode, only when RED will not clear', () => {
    const T0 = 1_760_000_010_000;   // a bucket boundary
    const BAD = 5000;               // works search: > 3000 ms average is RED
    const SEMANTIC_BAD = 9000;      // semantic: > 6500 ms
    const MIN = 60_000;
    let now = T0;
    let posts: string[] = [];

    function memState(initial: Record<string, unknown> = {}) {
        const store = new Map<string, unknown>(Object.entries(initial));
        return {
            store,
            storage: {
                get: async (k: string) => store.get(k),
                put: async (k: string, v: unknown) => { store.set(k, v); },
                setAlarm: async () => {},
            },
            blockConcurrencyWhile: async (fn: () => Promise<void>) => fn(),
            waitUntil: (_p: Promise<unknown>) => {},
        };
    }
    async function make(state = memState()) {
        const dobj = new SearchHealthController(state as any, { SLACK_WEBHOOK_URL: 'https://slack.test/hook' } as any);
        await new Promise((r) => setTimeout(r, 0));   // let the constructor's storage read finish
        return dobj;
    }
    // One bucket: n searches at ms each (null = a silent bucket, which reads GREEN), then the bucket rolls.
    async function bucketAt(dobj: SearchHealthController, ms: number | null) {
        if (ms !== null) {
            for (let i = 0; i < MIN_BUCKET_SAMPLES; i++) {
                await dobj.fetch(new Request('http://internal/observe', {
                    method: 'POST', body: JSON.stringify({ ms, status: 200, kind: 'search' }),
                }));
            }
        }
        now += BUCKET_MS;
        await dobj.alarm();
    }
    async function buckets(dobj: SearchHealthController, n: number, ms: number | null) {
        for (let i = 0; i < n; i++) await bucketAt(dobj, ms);
    }
    const view = async (dobj: SearchHealthController) =>
        (await dobj.fetch(new Request('http://internal/state'))).json<Record<string, any>>();
    const level = async (dobj: SearchHealthController) => (await view(dobj)).state as string;

    beforeEach(() => {
        now = T0 + 1000;
        posts = [];
        vi.spyOn(Date, 'now').mockImplementation(() => now);
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
            posts.push(JSON.parse(String(init?.body)).text);
            return new Response('ok');
        }));
    });
    afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

    it('a 10-min RED that lifts, and the whole episode, post nothing (ladder and transitions unchanged)', async () => {
        const dobj = await make();
        await buckets(dobj, 2, BAD);
        expect(await level(dobj)).toBe('RED');
        await buckets(dobj, 18, BAD);                  // RED held ~9 min
        while (await level(dobj) === 'RED') await bucketAt(dobj, null);
        expect(await level(dobj)).toBe('ORANGE');
        await buckets(dobj, 60, null);                 // walk down to GREEN, then 10 quiet min close the episode
        const v = await view(dobj);
        expect(v.state).toBe('GREEN');
        expect(v.episode.open).toBe(false);
        expect(posts).toEqual([]);
        expect([...v.recentTransitions].reverse().map((t: any) => `${t.from}->${t.to}`)).toEqual([
            'GREEN->YELLOW', 'YELLOW->RED', 'RED->ORANGE', 'ORANGE->YELLOW', 'YELLOW->GREEN',
        ]);
    });

    it('RED held 30 min posts one "needs a look", never repeats, and the episode closes with one ✅', async () => {
        const dobj = await make();
        await buckets(dobj, 2, BAD);                   // RED from here
        await buckets(dobj, 59, BAD);                  // 29.5 min
        expect(posts).toEqual([]);
        await bucketAt(dobj, BAD);                     // 30 min
        expect(posts).toHaveLength(1);
        expect(posts[0]).toMatch(/^🔴 \*OpenAlex search-health: needs a look\*/);
        expect(posts[0]).toMatch(/anonymous works search has been paused \(503\) for 30 min without a break/);
        expect(posts[0]).toMatch(/works Elasticsearch cluster/);
        expect(posts[0]).toContain('https://api.openalex.org/search-health ');
        expect((await view(dobj)).episode.needsLookPosted).toBe(true);
        await buckets(dobj, 60, BAD);                  // 60 min RED in total: still the one post
        expect(posts).toHaveLength(1);
        await buckets(dobj, 60, null);
        expect(await level(dobj)).toBe('GREEN');
        expect(posts).toHaveLength(2);
        expect(posts[1]).toMatch(/^✅ \*OpenAlex search-health: recovered\*/);
        const redMin = Number(posts[1].match(/(\d+) min of it paused \(RED\)/)![1]);
        expect(redMin).toBeGreaterThanOrEqual(61);
        expect(redMin).toBeLessThanOrEqual(63);
        expect((await view(dobj)).episode).toMatchObject({ open: false, redMin: 0, needsLookPosted: false });
    });

    it('short REDs that add up to 60 min in one episode post one "needs a look"', async () => {
        const dobj = await make();
        let stretches = 0;
        let longestMs = 0;
        while (posts.length === 0 && stretches < 10) {
            const start = now;
            await buckets(dobj, 20, BAD);              // ~10 min of trouble; RED caps its hold at 10 min
            while (await level(dobj) === 'RED') await bucketAt(dobj, null);
            expect(await level(dobj)).toBe('ORANGE');  // lifted to rationing: the same episode
            longestMs = Math.max(longestMs, now - start);
            stretches++;
        }
        expect(longestMs).toBeLessThan(15 * MIN);      // never near the 30-min continuous rule
        expect(stretches).toBeGreaterThanOrEqual(5);
        expect(posts).toHaveLength(1);
        expect(posts[0]).toMatch(/needs a look/);
        expect(posts[0]).toMatch(/has been paused \(503\) for 60 of the last \d+ min/);
        for (let i = 0; i < 3; i++) {                  // more of the same: still one post
            await buckets(dobj, 20, BAD);
            while (await level(dobj) === 'RED') await bucketAt(dobj, null);
        }
        expect(posts).toHaveLength(1);
        await buckets(dobj, 60, null);
        expect(posts).toHaveLength(2);
        expect(posts[1]).toMatch(/recovered/);
    });

    it('an ORANGE-only episode and a sub-threshold RED episode close silently, back to back', async () => {
        const dobj = await make();
        await bucketAt(dobj, 2000);                    // ORANGE-severity buckets
        await buckets(dobj, 3, 2000);
        expect(await level(dobj)).toBe('ORANGE');
        await buckets(dobj, 60, null);
        await buckets(dobj, 2, BAD);
        await buckets(dobj, 40, BAD);                  // RED ~20 min
        await buckets(dobj, 60, null);
        expect(await level(dobj)).toBe('GREEN');
        expect(posts).toEqual([]);
    });

    it('loads state stored before #2088 (no new fields) mid-RED without crashing or double-posting', async () => {
        const state = memState({ health: {
            level: 3, since: now - 12 * MIN, lastUnhealthyExit: 0, reclampStreak: 0,
            episodeOpen: true, episodeRedAlerted: true, episodeStartedAt: now - 14 * MIN, episodePeak: 3,
            redStartedAt: now - 12 * MIN,
        } });
        let dobj = await make(state);
        const v = await view(dobj);
        expect(v.state).toBe('RED');
        expect(v.episode).toMatchObject({ open: true, redMin: 12, needsLookPosted: false });
        await buckets(dobj, 35, BAD);                  // 12 + 17.5 = 29.5 min held
        expect(posts).toEqual([]);
        await bucketAt(dobj, BAD);
        expect(posts).toHaveLength(1);
        expect(posts[0]).toMatch(/for 30 min without a break/);
        const stored = state.store.get('health') as Record<string, unknown>;
        expect(stored).toMatchObject({ episodeNeedsLookPosted: true, redAccumMs: 0 });
        dobj = await make(state);                      // a deploy right after the post
        await buckets(dobj, 10, BAD);
        expect(posts).toHaveLength(1);
        await buckets(dobj, 60, null);
        expect(posts).toHaveLength(2);
        expect(posts[1]).toMatch(/recovered/);

        // A record from before v3.5 (level and since only) loads too, and stays quiet.
        const old = await make(memState({ health: { level: 0, since: now - 60 * MIN } }));
        expect((await view(old)).episode).toMatchObject({ open: false, redMin: 0, needsLookPosted: false });
        await buckets(old, 5, null);
        expect(posts).toHaveLength(2);
    });

    it('the semantic instance names its own search, cluster and ladder URL', async () => {
        const dobj = await make(memState({ profile: 'semantic' }));
        await buckets(dobj, 62, SEMANTIC_BAD);
        expect(posts).toHaveLength(1);
        expect(posts[0]).toMatch(/^🔴 \*OpenAlex semantic-health: needs a look\* — free and anonymous semantic search has been paused/);
        expect(posts[0]).toMatch(/semantic search \(vector\) cluster/);
        expect(posts[0]).toContain('https://api.openalex.org/search-health?ladder=semantic');
    });

    it('the test ping still posts, and describes the new policy', async () => {
        const dobj = await make();
        const r = await (await dobj.fetch(new Request('http://internal/test-slack', { method: 'POST' }))).json<any>();
        expect(r.sent).toBe(true);
        expect(posts).toHaveLength(1);
        expect(posts[0]).toMatch(/test ping.*only when a RED pause isn't clearing/);
    });
});
