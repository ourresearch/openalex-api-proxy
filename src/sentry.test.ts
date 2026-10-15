import { describe, it, expect, vi, afterEach } from 'vitest';
import { reportError, withErrorReporting } from './sentry';

// oxjob #1685: errors-only Sentry reporting. fetch is stubbed, so nothing leaves the test.
describe('sentry reporting', () => {
    afterEach(() => vi.unstubAllGlobals());

    it('sends at most 10 events a minute per isolate, drops sampled-out ones, keeps query strings out', async () => {
        const bodies: string[] = [];
        vi.stubGlobal('fetch', async (_u: string, init: RequestInit) => {
            bodies.push(String(init.body));
            return new Response('{}', { status: 200 });
        });
        const pending: Promise<unknown>[] = [];
        const env = { SENTRY_DSN: 'https://abc@o1.ingest.us.sentry.io/2' };
        const request = new Request('https://api.openalex.org/works/W1?api_key=SECRETKEY');
        await expect(withErrorReporting({ env, waitUntil: (p) => pending.push(p), request }, 'fetch', async () => {
            reportError(new Error('sampled out'), { site: 'test', sampleRate: 0 });
            for (let i = 0; i < 12; i++) reportError(new Error('boom ' + i), { site: 'test' });
            throw new TypeError('escaped');
        })).rejects.toThrow('escaped');
        await Promise.all(pending);
        expect(bodies.length).toBe(10);
        expect(bodies[0]).toContain('boom 0');
        expect(bodies[0]).toContain('"in_app":true');
        expect(bodies.join('')).not.toContain('SECRETKEY');
        expect(bodies.join('')).not.toContain('sampled out');
    });

    it('is a no-op without a DSN and never throws', () => {
        vi.stubGlobal('fetch', () => { throw new Error('should not be called'); });
        expect(() => reportError(new Error('x'), { site: 'test', inv: { env: {}, waitUntil: () => {} } })).not.toThrow();
        expect(() => reportError(new Error('x'), { site: 'test' })).not.toThrow();
    });
});
