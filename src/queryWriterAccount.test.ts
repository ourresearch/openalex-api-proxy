// /query/text tells the query writer which account asked (oxjob #1494): the key's user and organization ids, set from
// the key check, so its log line can say who asks in aggregate. Never the key; a caller's own copy of the headers is
// dropped, so a caller can't put a question on someone else's account.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { queryWriterRequest, QUERY_WRITER_USER_HEADER, QUERY_WRITER_ORG_HEADER } from './endpointClassifier';
import { runWorker } from './testHarness';

vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, params: string[]) {
            const base = { max_per_day: 10000, max_credits_per_day: 10000, is_grandfathered: false,
                onetime_credits_balance: 0, plan: null, rate_throttled: false, throttle_scope: null };
            if (params[0] === 'USERKEY1') return { rows: [{ ...base, user_id: 'user-asker', org_id: null }] };
            if (params[0] === 'ORGKEY1') return { rows: [{ ...base, user_id: null, org_id: 'org-asker' }] };
            return { rows: [] };
        }
        async end() {}
    },
}));

const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };

describe('queryWriterRequest', () => {
    it('sets the ids it is given and drops any the caller sent', async () => {
        const req = new Request('https://api.openalex.org/query/text', {
            method: 'POST', headers: { Authorization: 'Bearer K', [QUERY_WRITER_USER_HEADER]: 'user-forged', [QUERY_WRITER_ORG_HEADER]: 'org-forged' },
            body: '{"text":"kelp"}',
        });
        const fwd = queryWriterRequest('https://api.openalex.org/query/text', req, 'user-real', null);
        expect(fwd.headers.get(QUERY_WRITER_USER_HEADER)).toBe('user-real');
        expect(fwd.headers.get(QUERY_WRITER_ORG_HEADER)).toBeNull();
        expect(fwd.headers.get('Authorization')).toBe('Bearer K');
        expect(fwd.method).toBe('POST');
        expect(await fwd.text()).toBe('{"text":"kelp"}');
    });
});

describe('/query/text names the asking account to the query writer', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    async function ask(key: string) {
        const seen: Request[] = [];
        const writer = vi.fn(async (r: Request) => { seen.push(r); return new Response('{}', { status: 200, headers: { 'X-Credits-Cost': '300' } }); });
        const { res } = await runWorker('/query/text/kelp', {
            headers: { Authorization: `Bearer ${key}`, [QUERY_WRITER_USER_HEADER]: 'user-forged', [QUERY_WRITER_ORG_HEADER]: 'org-forged' },
            env: { ...HD, QUERY_TEXT_ACCOUNTS: '*', QUERY_WRITER: { fetch: writer } },
        });
        expect(res.status).toBe(200);
        expect(seen).toHaveLength(1);
        return seen[0].headers;
    }

    it("a person's key: the user id, no organization", async () => {
        const h = await ask('USERKEY1');
        expect(h.get(QUERY_WRITER_USER_HEADER)).toBe('user-asker');
        expect(h.get(QUERY_WRITER_ORG_HEADER)).toBeNull();
    });

    it("an organization's key: the organization id, no user", async () => {
        const h = await ask('ORGKEY1');
        expect(h.get(QUERY_WRITER_USER_HEADER)).toBeNull();
        expect(h.get(QUERY_WRITER_ORG_HEADER)).toBe('org-asker');
    });
});
