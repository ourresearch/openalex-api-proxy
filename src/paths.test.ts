// Slash trimming in linear time, with exactly the regexes' output (oxjob #1762).
import { describe, it, expect } from 'vitest';
import { trimSlashes, trimTrailingSlashes, normalizePath } from './paths';
import { classifyEndpoint } from './endpointClassifier';
import { isChangefilesBrowsePath, isChangefileDownloadPath, isSnapshotCredentialsPath } from './changefilesPaths';

// The regexes these replace (src/index.ts, endpointClassifier.ts, changefilesPaths.ts). Short inputs only.
const oldTrim = (p: string) => p.replace(/^\/+|\/+$/g, '');
const oldTrimStar = (p: string) => p.replace(/^\/*|\/*$/g, '');
const oldTrimTrailing = (p: string) => p.replace(/\/+$/, '');

const SAMPLES = ['', '/', '//', '///', 'a', '/a', 'a/', '/a/', '//a//', '/works', '/works/', '/works//x', '/works/W1/',
    '//changefiles//2026-01-01//', '/changefiles/2026-01-01/works.jsonl.gz', '/%2F/x/', '/a/b/c', 'a//b', '/RATE-LIMIT/',
    '/content//changefiles/2026-10-20/x.parquet/', ' / ', '\\/\\'];

describe('trimSlashes, trimTrailingSlashes, normalizePath', () => {
    it('return exactly what the regexes returned, on representative paths', () => {
        for (const p of SAMPLES) {
            expect(trimSlashes(p), p).toBe(oldTrim(p));
            expect(trimSlashes(p), p).toBe(oldTrimStar(p));
            expect(trimTrailingSlashes(p), p).toBe(oldTrimTrailing(p));
            expect(normalizePath(p), p).toBe(oldTrim(p).toLowerCase());
        }
    });

    it('and on every string of slashes and letters up to 10 long', () => {
        let n = 0;
        const all = (s: string): void => {
            if (s.length > 0) {
                expect(trimSlashes(s)).toBe(oldTrim(s));
                expect(trimTrailingSlashes(s)).toBe(oldTrimTrailing(s));
                n++;
            }
            if (s.length < 10) { all(s + '/'); all(s + 'a'); }
        };
        all('');
        expect(n).toBe(2046);
    });

    it('stay fast on a 16K interior run of slashes, through every matcher that normalizes a path', () => {
        const attack = '/works' + '/'.repeat(16_000) + 'x';
        const t0 = performance.now();
        expect(trimSlashes(attack)).toBe(attack.slice(1));
        expect(trimTrailingSlashes(attack)).toBe(attack);
        expect(normalizePath(attack)).toBe(attack.slice(1));
        classifyEndpoint(attack);
        isChangefilesBrowsePath(attack);
        isChangefileDownloadPath(attack);
        isSnapshotCredentialsPath(attack);
        // The regexes took ~100 ms a pass on this input (quadratic); the scans take microseconds.
        expect(performance.now() - t0).toBeLessThan(50);
    });
});
