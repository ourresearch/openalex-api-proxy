// Sync filters through OQL/OQO are a paid feature (oxjob #1689): the rule, the meta.x_query reader, and the gate
// driven through the whole Worker against a stub origin that answers the way elastic-api did on 2026-10-16.
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
    syncFieldInParams, syncFieldInUrl, syncColumnInOqo, syncFieldInXQuery, requestOqlText, mightNameSyncField,
    MetaScanner, readXQuery, oqlSyncMessage,
} from './syncGate';
import { runWorker, fakeState } from './testHarness';
import { RateLimiter } from './rateLimiter';

vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, params: string[]) {
            const plans: Record<string, string | null> = { PAIDKEY1: 'premium-1M', MEMBERK1: 'member-plus', FREEKEY1: null };
            if (!(params[0] in plans)) return { rows: [] };
            return { rows: [{ max_per_day: 100000, max_credits_per_day: 100000, is_grandfathered: false,
                onetime_credits_balance: 0, plan: plans[params[0]], rate_throttled: false, throttle_scope: null,
                user_id: `user-${params[0]}`, org_id: null }] };
        }
        async end() {}
    },
}));

const P = (q: string) => new URLSearchParams(q);

describe('syncFieldInParams: the one rule for classic URLs and x_query.url', () => {
    it('finds a sync filter, and names the field and the clause', () => {
        expect(syncFieldInParams(P('filter=from_updated_date:2026-10-15'))).toEqual(
            { kind: 'filter', field: 'from_updated_date', clause: 'from_updated_date:2026-10-15' });
        expect(syncFieldInParams(P('filter=type:article,to_created_date:2026-01-01,is_oa:true'))?.clause)
            .toBe('to_created_date:2026-01-01');
        expect(syncFieldInParams(P('filter=updated_date:%3E2026-10-15'))?.clause).toBe('updated_date:>2026-10-15');
        expect(syncFieldInParams(P('filter=created_date:<2026-01-01'))?.field).toBe('created_date');
    });
    it('finds a sync sort', () => {
        expect(syncFieldInParams(P('filter=publication_year:2025&sort=updated_date:desc'))).toEqual(
            { kind: 'sort', field: 'updated_date', clause: 'updated_date:desc' });
        expect(syncFieldInParams(P('sort=cited_by_count:desc,created_date'))?.field).toBe('created_date');
    });
    it('checks every duplicate param, not just the first', () => {
        expect(syncFieldInParams(P('filter=type:article&filter=from_updated_date:2026-10-15'))?.kind).toBe('filter');
        expect(syncFieldInParams(P('sort=cited_by_count&sort=updated_date'))?.kind).toBe('sort');
    });
    it('catches hyphenated names, which the API reads as the underscore ones (a free key got 40.9M rows this way)', () => {
        expect(syncFieldInParams(P('filter=from-updated-date:2026-10-15'))?.field).toBe('from-updated-date');
        expect(syncFieldInParams(P('filter=from_updated-date:2026-10-15'))).not.toBeNull();
        expect(syncFieldInParams(P('sort=updated-date:desc'))?.kind).toBe('sort');
    });
    it('catches a negated value (x_query renders `not updated since` as from_updated_date:!date)', () => {
        expect(syncFieldInParams(P('filter=from_updated_date:%212026-10-01,publication_year:2026'))?.clause)
            .toBe('from_updated_date:!2026-10-01');
    });
    it('leaves the free axes alone', () => {
        expect(syncFieldInParams(P('filter=from_publication_date:2026-10-15&sort=publication_date:desc'))).toBeNull();
        expect(syncFieldInParams(P('filter=publication_year:2026&sort=cited_by_count:desc'))).toBeNull();
        expect(syncFieldInParams(P(''))).toBeNull();
    });
});

describe('syncFieldInUrl: x_query.url as elastic-api writes it', () => {
    it('reads the field out of the canonical classic URL (live shapes, 2026-10-16)', () => {
        expect(syncFieldInUrl('/works?filter=from_updated_date:2026-10-15&per_page=1')?.field).toBe('from_updated_date');
        expect(syncFieldInUrl('/works?filter=from_created_date:2026-10-15&per_page=100')?.field).toBe('from_created_date');
        expect(syncFieldInUrl('/authors?filter=from_updated_date:2026-10-15&per_page=100')?.field).toBe('from_updated_date');
        expect(syncFieldInUrl('/works?filter=updated_date:%3C2026-10-15,publication_year:2026&per_page=1')?.clause)
            .toBe('updated_date:<2026-10-15');
        expect(syncFieldInUrl('/works?filter=publication_year:2025&sort=updated_date:desc&per_page=1')?.kind).toBe('sort');
        expect(syncFieldInUrl('/works?filter=from_updated_date:2026-10-15&group_by=type&per_page=1')).not.toBeNull();
    });
    it('passes free URLs, and anything that is not a URL', () => {
        expect(syncFieldInUrl('/works?filter=publication_year:2026&per_page=1')).toBeNull();
        for (const v of [null, undefined, '', 42, {}]) expect(syncFieldInUrl(v)).toBeNull();
    });
});

describe('syncColumnInOqo: the canonical OQO, for queries a URL cannot say', () => {
    it('finds a sync column in a top-level leaf, a nested branch, a subquery and sort_by', () => {
        expect(syncColumnInOqo({ get_rows: 'works', filter_rows: [{ column_id: 'from_updated_date', value: '2026-10-15' }] }))
            .toBe('from_updated_date');
        expect(syncColumnInOqo({ get_rows: 'works', filter_rows: [{ column_id: 'publication_year', value: 2026 },
            { join: 'or', filters: [{ column_id: 'type', value: 'article' }, { column_id: 'created_date', value: '2026-01-01', operator: '<' }] }] }))
            .toBe('created_date');
        expect(syncColumnInOqo({ get_rows: 'works', filter_rows: [{ column_id: 'referenced_works', value:
            { get_rows: 'works', filter_rows: [{ column_id: 'from_updated_date', value: '2026-10-15' }] } }] }))
            .toBe('from_updated_date');
        expect(syncColumnInOqo({ get_rows: 'works', sort_by: [{ column_id: 'updated_date', direction: 'desc' }] })).toBe('updated_date');
        expect(syncColumnInOqo({ get_rows: 'works', sort_by_column: 'created_date', sort_by_order: 'desc' })).toBe('created_date');
    });
    it('passes OQOs on free columns, and a value that merely mentions a sync column', () => {
        expect(syncColumnInOqo({ get_rows: 'works', filter_rows: [{ column_id: 'publication_date', value: '2026-10-15', operator: '>=' }],
            group_by: [{ column_id: 'type' }] })).toBeNull();
        expect(syncColumnInOqo({ get_rows: 'works', filter_rows: [{ column_id: 'display_name.search', value: 'updated_date' }] })).toBeNull();
        expect(syncColumnInOqo(null)).toBeNull();
        expect(syncColumnInOqo('from_updated_date')).toBeNull();
    });
});

describe('syncFieldInXQuery', () => {
    it('uses the URL, and the OQO when the URL is null (nested AND/OR, a pipeline summary)', () => {
        expect(syncFieldInXQuery({ url: '/works?filter=from_updated_date:2026-10-15', oqo: {} })).toBe('from_updated_date');
        expect(syncFieldInXQuery({ url: null, oqo: { get_rows: 'works', filter_rows: [{ column_id: 'from_created_date', value: '2026-10-15' }],
            group_by: [{ column_id: 'type' }], calculate: [{ measure: 'count' }] } })).toBe('from_created_date');
    });
    it('is null when x_query is missing or names no sync field (the gate fails open)', () => {
        expect(syncFieldInXQuery(undefined)).toBeNull();
        expect(syncFieldInXQuery({ url: '/works?filter=publication_year:2026', oqo: { get_rows: 'works' } })).toBeNull();
        expect(syncFieldInXQuery({})).toBeNull();
    });
});

describe('requestOqlText and the prefilter', () => {
    it('collects GET oql/oqo params on any path, and a POST body oql/oqo with its sort sibling', () => {
        expect(requestOqlText(P('oql=works where updated date >= 2026-10-15'), null)).toBe('works where updated date >= 2026-10-15');
        expect(requestOqlText(P('oqo={"get_rows":"works"}'), null)).toBe('{"get_rows":"works"}');
        expect(requestOqlText(P(''), { oql: 'works where year is 2025', sort: 'updated_date:desc' }))
            .toBe('works where year is 2025\nupdated_date:desc');
        expect(requestOqlText(P(''), { oqo: { get_rows: 'works' } })).toBe('{"get_rows":"works"}');
    });
    it('is null for a request without OQL/OQO', () => {
        expect(requestOqlText(P('filter=from_updated_date:2026-10-15'), null)).toBeNull();
        expect(requestOqlText(P(''), { sort: 'updated_date' })).toBeNull();
        expect(requestOqlText(P(''), ['oql'])).toBeNull();
    });
    it('reads JSON-escaped OQO the way the engine will, so \\u escapes cannot slip past the prefilter', () => {
        const escaped = '{"get_rows":"works","filter_rows":[{"column_id":"from_\\u0075pdated\\u005fdate","value":"2026-10-15"}]}';
        const text = requestOqlText(P(`oqo=${encodeURIComponent(escaped)}`), null)!;
        expect(text).toContain('from_updated_date');
        expect(mightNameSyncField(text)).toBe(true);
    });
    it('matches every wording the grammar has for the two dates, and not ordinary queries', () => {
        for (const q of ['works where updated date >= 2026-10-15', 'works where added since 2026-10-15', 'works where UPDATED SINCE 2026-10-15',
            'works where created date < 2026-01-01', 'works where updated on or after 2026-10-15', '{"column_id":"from_updated_date"}']) {
            expect(mightNameSyncField(q)).toBe(true);
        }
        expect(mightNameSyncField('works where title has "coral reefs" and year is 2024')).toBe(false);
    });
    it('names the field in a message like the classic one', () => {
        expect(oqlSyncMessage('from_updated_date')).toBe('OQL that filters or sorts by "from_updated_date" is part of daily sync, which comes with the Member+ and Partner plans. See https://help.openalex.org/access/sync/ for details.');
    });
});

const LIVE_BODY = JSON.stringify({
    meta: { count: 40919494, db_response_time_ms: 33, page: 1, per_page: 1, groups_count: null,
        x_query: { oql: 'get works where updated since 2026-10-15', oqo: { get_rows: 'works', filter_rows: [{ column_id: 'from_updated_date', value: '2026-10-15' }] },
            url: '/works?filter=from_updated_date:2026-10-15&per_page=1' },
        cost: { credits: 1, usd: 0.0001 } },
    results: [{ id: 'https://openalex.org/W1', title: 'a {tricky} "title" with } and \\ and "meta": {' }],
    group_by: [],
});

describe('MetaScanner', () => {
    it('finds meta whatever the chunk boundaries', () => {
        for (let cut = 1; cut < LIVE_BODY.length; cut += 7) {
            const s = new MetaScanner();
            const done = s.push(LIVE_BODY.slice(0, cut)) || s.push(LIVE_BODY.slice(cut));
            expect(done).toBe(true);
            expect((s.meta as any).x_query.url).toBe('/works?filter=from_updated_date:2026-10-15&per_page=1');
        }
    });
    it('stops at the end of meta without needing the rest', () => {
        const s = new MetaScanner();
        expect(s.push(LIVE_BODY.slice(0, LIVE_BODY.indexOf('"results"')))).toBe(true);
        expect((s.meta as any).count).toBe(40919494);
    });
    it('is not fooled by braces and quotes inside strings, or by "meta" as a value', () => {
        const s = new MetaScanner();
        s.push('{"error": "meta", "note": "{\\"meta\\": {}}", "meta": {"x_query": {"url": "/works?x={}"}}, "results": []}');
        expect(s.meta).toEqual({ x_query: { url: '/works?x={}' } });
    });
    it('finds meta after other keys, and reports no meta for bodies without one', () => {
        const later = new MetaScanner();
        later.push('{"results": [{"meta": {"x": 1}}], "meta": {"count": 2}}');
        expect(later.meta).toEqual({ count: 2 });
        for (const body of ['{"msg": "Don\'t panic"}', '[{"meta": {}}]', '{"meta": null, "results": []}', '{"meta": [1, 2]}']) {
            const s = new MetaScanner();
            expect(s.push(body)).toBe(true);
            expect(s.meta).toBeUndefined();
        }
    });
});

function streamOf(chunks: string[], onPull?: (i: number) => void): ReadableStream<Uint8Array> {
    const enc = new TextEncoder();
    let i = 0;
    return new ReadableStream({
        pull(controller) {
            onPull?.(i);
            if (i < chunks.length) controller.enqueue(enc.encode(chunks[i++]));
            else controller.close();
        },
    });
}

describe('readXQuery', () => {
    it('returns meta.x_query and reads no further than meta', async () => {
        const pulled: number[] = [];
        const head = LIVE_BODY.slice(0, LIVE_BODY.indexOf('"results"'));
        const xq = await readXQuery(streamOf([head.slice(0, 50), head.slice(50), '"results": [' + 'x'.repeat(1000)], i => pulled.push(i)));
        expect((xq as any).url).toBe('/works?filter=from_updated_date:2026-10-15&per_page=1');
        expect(Math.max(...pulled)).toBe(1);
    });
    it('decodes multi-byte characters split across chunks', async () => {
        const bytes = new TextEncoder().encode('{"meta": {"x_query": {"oql": "works where title has \\"café\\"", "url": null}}}');
        const cut = bytes.indexOf(0xc3) + 1;  // inside the é
        const stream = new ReadableStream<Uint8Array>({ start(c) { c.enqueue(bytes.slice(0, cut)); c.enqueue(bytes.slice(cut)); c.close(); } });
        expect(((await readXQuery(stream)) as any).oql).toBe('works where title has "café"');
    });
    it('fails open (undefined) on no meta, a broken stream, or a meta past the byte cap', async () => {
        expect(await readXQuery(streamOf(['{"msg": "Don\'t panic"}']))).toBeUndefined();
        const broken = new ReadableStream<Uint8Array>({ pull(c) { c.error(new Error('reset')); } });
        expect(await readXQuery(broken)).toBeUndefined();
        expect(await readXQuery(streamOf(['{"meta": {"x_query": {"url": "', 'x'.repeat(200), '"}}}']), 100)).toBeUndefined();
    });
});

// ---- the gate through the whole Worker ----

const json = (body: unknown, status = 200, type = 'application/json') =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'Content-Type': type } });

function originAnswering(xQuery: unknown, extra: Record<string, unknown> = {}) {
    const calls: string[] = [];
    const fetch = async (input: Request | string) => {
        calls.push(typeof input === 'string' ? input : input.url);
        return json({ meta: { count: 40919494, page: 1, per_page: 25, ...(xQuery === undefined ? {} : { x_query: xQuery }) },
            results: [{ id: 'https://openalex.org/W1' }], ...extra });
    };
    return { fetch, calls };
}

// A real RateLimiter per bucket, recording which endpoints the Worker called (to see the refund).
function recordingLimiter() {
    const limiters = new Map<string, RateLimiter>();
    const calls: { path: string; credits?: number }[] = [];
    return {
        calls,
        RATE_LIMITER: {
            idFromName: (n: string) => n,
            get: (name: string) => ({
                fetch: async (u: string, init?: RequestInit) => {
                    if (!limiters.has(name)) {
                        limiters.set(name, new RateLimiter(fakeState() as any));
                        await new Promise(r => setTimeout(r, 0));
                    }
                    calls.push({ path: new URL(u).pathname, credits: init?.body ? JSON.parse(String(init.body)).credits : undefined });
                    return limiters.get(name)!.fetch(new Request(u, init));
                },
            }),
        },
    };
}

const UPDATED_URL_XQ = { oql: 'get works where updated since 2026-10-15', url: '/works?filter=from_updated_date:2026-10-15&per_page=25',
    oqo: { get_rows: 'works', filter_rows: [{ column_id: 'from_updated_date', value: '2026-10-15' }] } };
const OQL_UPDATED = '/?oql=' + encodeURIComponent('works where updated date >= 2026-10-15') + '&cursor=*';
const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };

describe('the OQL/OQO sync gate, through the Worker (oxjob #1689)', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    it('refuses a keyless OQL "updated date" query with the classic 429, refunds its credit, and logs it like the classic refusal', async () => {
        const origin = originAnswering(UPDATED_URL_XQ);
        const limiter = recordingLimiter();
        const { res, rows } = await runWorker(OQL_UPDATED, { fetch: origin.fetch, env: { RATE_LIMITER: limiter.RATE_LIMITER } });
        expect(res.status).toBe(429);
        expect(await res.json()).toEqual({ error: 'Plan upgrade required', message: oqlSyncMessage('from_updated_date') });
        expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
        expect(origin.calls).toHaveLength(1);
        expect(limiter.calls.filter(c => c.path === '/check').map(c => c.credits)).toEqual([1]);
        expect(limiter.calls.filter(c => c.path === '/refund').map(c => c.credits)).toEqual([1]);
        const row = rows.find(r => r.doubles[1] === 429)!;
        expect(row.blobs[4]).toBe('main');
        expect(row.doubles[4]).toBe(0);  // creditCost
    });

    it('refuses a POSTed OQL "added since" query (created date) and a POSTed OQO', async () => {
        const added = { url: '/works?filter=from_created_date:2026-10-15&per_page=25', oqo: {} };
        for (const body of [{ oql: 'works where added since 2026-10-15' },
            { oqo: { get_rows: 'works', filter_rows: [{ column_id: 'from_created_date', value: '2026-10-15' }] } }]) {
            const { res } = await runWorker('/', { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
                fetch: originAnswering(added).fetch });
            expect(res.status).toBe(429);
            expect((await res.json() as any).message).toContain('"from_created_date"');
        }
    });

    it('refuses a query the URL form cannot say (url null), from the OQO', async () => {
        const nested = { url: null, oqo: { get_rows: 'works', filter_rows: [{ column_id: 'from_updated_date', value: '2026-10-15' },
            { join: 'or', filters: [{ column_id: 'display_name.search.exact', value: 'cancer' }, { column_id: 'abstract.search.exact', value: 'tumor' }] }] } };
        const q = '/?oql=' + encodeURIComponent('works where updated since 2026-10-15 and (title has "cancer" or abstract has "tumor")');
        expect((await runWorker(q, { fetch: originAnswering(nested).fetch })).res.status).toBe(429);
    });

    it('refuses a sync sort riding as a POST body sibling', async () => {
        const sorted = { url: '/works?filter=publication_year:2025&sort=updated_date:desc&per_page=1', oqo: {} };
        const { res } = await runWorker('/', { method: 'POST', body: JSON.stringify({ oql: 'works where year is 2025', sort: 'updated_date:desc' }),
            headers: { 'Content-Type': 'application/json' }, fetch: originAnswering(sorted).fetch });
        expect(res.status).toBe(429);
        expect((await res.json() as any).message).toContain('"updated_date"');
    });

    it('refuses a free key, and lets paid plans (premium, member-plus) through with the answer intact', async () => {
        const free = await runWorker(OQL_UPDATED, { headers: { Authorization: 'Bearer FREEKEY1' }, env: HD, fetch: originAnswering(UPDATED_URL_XQ).fetch });
        expect(free.res.status).toBe(429);
        for (const key of ['PAIDKEY1', 'MEMBERK1']) {
            const paid = await runWorker(OQL_UPDATED, { headers: { Authorization: `Bearer ${key}` }, env: HD, fetch: originAnswering(UPDATED_URL_XQ).fetch });
            expect(paid.res.status).toBe(200);
            expect((await paid.res.json() as any).meta.count).toBe(40919494);
        }
    });

    it('passes free queries untouched, byte for byte, including a large answer', async () => {
        // No ES-took sample clone (10% of requests): the harness awaits waitUntil work before the body is read, so a
        // large sampled body stalls in Node's tee whatever the path (plain /works lists too). Not a production effect.
        vi.spyOn(Math, 'random').mockReturnValue(0.99);
        const free = { url: '/works?filter=from_publication_date:2026-10-15', oqo: { get_rows: 'works' } };
        const body = JSON.stringify({ meta: { count: 3, x_query: free }, results: Array.from({ length: 2000 }, (_, i) => ({ id: `W${i}`, t: 'x'.repeat(50) })) });
        const q = '/?oql=' + encodeURIComponent('works where published since 2026-10-15 and created date is not mentioned');
        const { res } = await runWorker(q, { fetch: async () => json(body) });
        expect(res.status).toBe(200);
        expect(await res.text()).toBe(body);
    });

    it('does not read answers to queries the prefilter rules out', async () => {
        // A query with none of the sync words is never checked, even if its answer named a sync field.
        const q = '/?oql=' + encodeURIComponent('works where title has "coral reefs"');
        expect((await runWorker(q, { fetch: originAnswering(UPDATED_URL_XQ).fetch })).res.status).toBe(200);
    });

    it('fails open when the answer has no x_query, is not JSON, or is an error', async () => {
        expect((await runWorker(OQL_UPDATED, { fetch: originAnswering(undefined).fetch })).res.status).toBe(200);
        expect((await runWorker(OQL_UPDATED, { fetch: async () => json('type,count\narticle,5\n', 200, 'text/csv') })).res.status).toBe(200);
        expect((await runWorker(OQL_UPDATED, { fetch: async () => json({ validation: { valid: false } }, 400) })).res.status).toBe(400);
    });

    it('still refuses a hyphenated classic filter at the edge, before the origin', async () => {
        const origin = originAnswering(undefined);
        const { res } = await runWorker('/works?filter=from-updated-date:2026-10-15', { fetch: origin.fetch });
        expect(res.status).toBe(429);
        expect((await res.json() as any).message).toBe('The "from-updated-date:2026-10-15" filter is part of daily sync, which comes with the Member+ and Partner plans. See https://help.openalex.org/access/sync/ for details.');
        expect(origin.calls).toHaveLength(0);
    });
});

// A POST body the gates can't read is refused, not forwarded: the origin's get_json also reads UTF-16/32 JSON and
// NaN, which JSON.parse refuses, so such a body rode past the sync gate and the rerank price (oxjob #1762).
describe('a POST body must be a UTF-8 JSON object', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    const ADDED = { oql: 'works where added since 2026-10-15' };
    const post = (body: BodyInit | undefined, origin = originAnswering({ url: '/works?filter=from_created_date:2026-10-15', oqo: {} })) =>
        runWorker('/', { method: 'POST', body, headers: { 'Content-Type': 'application/json' }, fetch: origin.fetch })
            .then(r => ({ ...r, origin }));

    it('refuses UTF-16 JSON (with or without a BOM) before the limiter and the origin', async () => {
        for (const bytes of [Buffer.from('﻿' + JSON.stringify(ADDED), 'utf16le'), Buffer.from(JSON.stringify(ADDED), 'utf16le')]) {
            const { res, checks, origin } = await post(new Uint8Array(bytes));
            expect(res.status).toBe(400);
            expect(checks).toEqual([]);
            expect(origin.calls).toEqual([]);
        }
    });

    it('refuses NaN, and JSON that is not an object', async () => {
        for (const body of ['{"oql": "works where added since 2026-10-15", "page": NaN}', 'NaN', '[1]', '"works"', 'null', '{oql: 1}']) {
            const { res, origin } = await post(body);
            expect(res.status, body).toBe(400);
            expect(origin.calls).toEqual([]);
        }
    });

    it('a JSON object is read and forwarded as before; an empty body is forwarded as before', async () => {
        const plain = originAnswering(undefined);
        expect((await post(JSON.stringify({ oql: 'works where title has "coral reefs"' }), plain)).res.status).toBe(200);
        expect((await post(JSON.stringify(ADDED))).res.status).toBe(429);  // the sync gate still reads it
        const empty = originAnswering(undefined);
        expect((await post(undefined, empty)).res.status).toBe(200);
        expect(empty.calls).toHaveLength(1);
    });
});
