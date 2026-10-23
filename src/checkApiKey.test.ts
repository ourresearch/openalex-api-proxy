// The key lookup fails open only when the database can't answer, never because the request's own key made it throw
// (oxjob #1762): ?api_key=%00x made Postgres refuse the bound value, and the catch-all served it as a valid
// 100K-credit key, past the keyless ladders and into /query/text.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { isDataException } from './index';
import { runWorker } from './testHarness';

const pgError = (code: string, message: string) => Object.assign(new Error(message), { code, severity: 'ERROR' });
const db = vi.hoisted(() => ({ queried: [] as string[] }));
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, [key]: string[]) {
            db.queried.push(key);
            // Postgres refuses a NUL in a text parameter (22021); the others stand for each kind of failure.
            if (key.includes('\u0000')) throw pgError('22021', 'invalid byte sequence for encoding "UTF8": 0x00');
            if (key === 'data-error-key') throw pgError('22P05', 'untranslatable character');
            if (key === 'outage-key') throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
            if (key === 'rotated-password-key') throw pgError('28P01', 'password authentication failed');
            return { rows: [] };
        }
        async end() {}
    },
}));

const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };

describe('isDataException', () => {
    it('is SQLSTATE class 22 only', () => {
        expect(isDataException(pgError('22021', 'x'))).toBe(true);
        expect(isDataException(pgError('22P05', 'x'))).toBe(true);
        for (const e of [pgError('28P01', 'x'), pgError('08006', 'x'), { code: 'ECONNREFUSED' }, new Error('x'), null, undefined]) {
            expect(isDataException(e)).toBe(false);
        }
    });
});

describe('a key the request makes the lookup refuse is unknown, not valid (oxjob #1762)', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); db.queried.length = 0; });

    it('?api_key=%00x is refused with a 401 before the database or the limiter', async () => {
        const { res, checks } = await runWorker('/works?api_key=%00x', { env: HD });
        expect(res.status).toBe(401);
        expect(checks).toEqual([]);
        expect(db.queried).toEqual([]);
    });

    it('and never reaches /query/text', async () => {
        const writer = vi.fn(async () => new Response('{}', { status: 200, headers: { 'X-Credits-Cost': '300' } }));
        const { res } = await runWorker('/query/text/coral%20reefs?api_key=%00x', {
            env: { ...HD, QUERY_TEXT_ACCOUNTS: '*', QUERY_WRITER: { fetch: writer } },
        });
        expect(res.status).toBe(401);
        expect(writer).not.toHaveBeenCalled();
    });

    it('a data exception from the database for a well-formed key is an unknown key too', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {}); // the lookup failure is logged
        const { res, checks } = await runWorker('/works?api_key=data-error-key', { env: HD });
        expect(res.status).toBe(401);
        expect(checks).toEqual([]);
    });

    it('an outage still fails open (connection refused, or a rotated database password)', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {});
        for (const key of ['outage-key', 'rotated-password-key']) {
            const { res, checks } = await runWorker(`/works?api_key=${key}`, { env: HD });
            expect(res.status).toBe(200);
            expect(checks).toEqual([{ bucket: `credits:${key}`, dailyLimit: 100000, perSecondLimit: 50 }]);
        }
    });
});
