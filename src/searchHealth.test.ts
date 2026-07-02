import { describe, it, expect } from 'vitest';
import {
    bucketSeverity,
    nextLevel,
    newBucket,
    MIN_BUCKET_SAMPLES,
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
        expect(bucketSeverity(bucket(100, 700))).toBe(0);   // bound is exclusive
        expect(bucketSeverity(bucket(100, 800))).toBe(1);   // YELLOW > 700ms
        expect(bucketSeverity(bucket(100, 2000))).toBe(2);  // ORANGE > 1.5s
        expect(bucketSeverity(bucket(100, 8000))).toBe(3);  // RED > 3s (07-01 shape)
    });

    it('maps 5xx share to the ladder independently of latency', () => {
        expect(bucketSeverity(bucket(100, 200, 1))).toBe(0);   // 1% errors
        expect(bucketSeverity(bucket(100, 200, 5))).toBe(1);   // 5% → YELLOW
        expect(bucketSeverity(bucket(100, 200, 15))).toBe(2);  // 15% → ORANGE
        expect(bucketSeverity(bucket(100, 200, 68))).toBe(3);  // 68% 504s (07-01) → RED
    });

    it('takes the worse of latency and error signals', () => {
        expect(bucketSeverity(bucket(100, 800, 15))).toBe(2); // YELLOW avg, ORANGE errors
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

    it('holds on a single bad bucket (no one-blip escalation)', () => {
        expect(nextLevel(G, [G, G, R])).toBe(G);
    });

    it('escalates after 2 consecutive qualifying buckets', () => {
        expect(nextLevel(G, [G, Y, Y])).toBe(Y);
        expect(nextLevel(Y, [Y, O, O])).toBe(O);
    });

    it('jumps straight to the worst common floor (00:00-batch shape)', () => {
        expect(nextLevel(G, [G, R, R])).toBe(R);
        expect(nextLevel(G, [Y, R])).toBe(Y); // both qualify ≥ YELLOW only
    });

    it('does not treat a mixed pair as escalation past the floor', () => {
        expect(nextLevel(O, [R, Y])).toBe(O); // floor Y is below current O → hold
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
});
