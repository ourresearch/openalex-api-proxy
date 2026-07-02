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
});
