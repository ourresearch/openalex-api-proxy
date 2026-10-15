import { describe, it, expect } from 'vitest';
import { metaNoticeTransform, wantsKeylessNotice, keylessNoticeFor } from './keylessNotice';
import { API_ROOT } from './apiRoot';

const enc = new TextEncoder();
const NOTICE = 'Say "hi" to the key\\ page';  // quotes and a backslash: the splice must JSON-escape it

async function through(chunks: (string | Uint8Array)[], notice = NOTICE): Promise<string> {
    const body = new ReadableStream<Uint8Array>({
        start(c) {
            for (const ch of chunks) c.enqueue(typeof ch === 'string' ? enc.encode(ch) : ch);
            c.close();
        },
    });
    return new Response(body.pipeThrough(metaNoticeTransform(notice))).text();
}

const LIST = '{"meta": {"count": 327083984, "db_response_time_ms": 171, "page": 1, "per_page": 1}, "results": [{"id": "W1"}], "group_by": []}';

describe('metaNoticeTransform (oxjob #1686)', () => {
    it("prefix present: the notice becomes meta's first key and everything else is unchanged", async () => {
        const out = await through([LIST]);
        const parsed = JSON.parse(out);
        expect(Object.keys(parsed.meta)[0]).toBe('notice');
        expect(parsed.meta.notice).toBe(NOTICE);
        expect(out.replace(`"notice": ${JSON.stringify(NOTICE)}, `, '')).toBe(LIST);
    });

    it('an empty meta gets the notice without a dangling comma', async () => {
        const out = await through(['{"meta": {}, "results": []}']);
        expect(JSON.parse(out)).toEqual({ meta: { notice: NOTICE }, results: [] });
    });

    it.each([
        ['a singleton record (no meta)', '{"id":"https://openalex.org/W2741809807","doi":"https://doi.org/10.7717/peerj.4375"}'],
        ['compact meta, no space', '{"meta":{"count":1},"results":[]}'],
        ['meta not first', '{"results": [], "meta": {"count": 1}}'],
        ['whitespace after the opening', '{"meta": { "count": 1}}'],
        ['a JSON array', '[{"meta": {"count": 1}}]'],
        ['shorter than the opening', '{}'],
        ['exactly the opening, then the end', '{"meta": {'],
    ])('prefix absent (%s): passed through byte for byte', async (_label, body) => {
        expect(await through([body])).toBe(body);
    });

    it('empty body: empty out, no throw', async () => {
        expect(await through([])).toBe('');
        expect(await through([new Uint8Array(0)])).toBe('');
    });

    it('the opening split across chunks, at every position', async () => {
        const want = await through([LIST]);
        for (let i = 1; i <= 14; i++) {
            expect(await through([LIST.slice(0, i), LIST.slice(i)])).toBe(want);
        }
        expect(await through([...LIST].map(ch => ch))).toBe(want);  // one byte per chunk
        expect(await through(['', '{"me', '', 'ta": {', '"count": 1}}'])).toBe(`{"meta": {"notice": ${JSON.stringify(NOTICE)}, "count": 1}}`);
    });

    it('the opening split across chunks, prefix absent: passed through', async () => {
        const body = '{"id":"https://openalex.org/W1","title":"x"}';
        expect(await through([body.slice(0, 3), body.slice(3, 5), body.slice(5)])).toBe(body);
    });

    it('a multi-MB body: only the opening is touched, later chunks pass as they came', async () => {
        const filler = 'x'.repeat(64 * 1024);
        const chunks = [LIST.slice(0, -1), ...Array.from({ length: 64 }, () => `, "f": "${filler}"`), '}'];
        const out = await through(chunks);
        expect(out.length).toBe(chunks.join('').length + `"notice": ${JSON.stringify(NOTICE)}, `.length);
        expect(JSON.parse(out).meta.notice).toBe(NOTICE);
    });

    it('multi-byte UTF-8 split mid-character after the opening survives', async () => {
        const body = enc.encode('{"meta": {"q": "café ☕"}}');
        const out = await through([body.subarray(0, 21), body.subarray(21)]);
        expect(JSON.parse(out).meta).toEqual({ notice: NOTICE, q: 'café ☕' });
    });
});

describe('wantsKeylessNotice (oxjob #1686)', () => {
    const json = new Headers({ 'Content-Type': 'application/json' });
    const base = { method: 'GET', endpointType: 'list', status: 200, headers: json, apiKey: null, trustedUi: false, verifiedAssistant: false };

    it('a keyless 200 JSON GET or POST', () => {
        expect(wantsKeylessNotice(base)).toBe(true);
        expect(wantsKeylessNotice({ ...base, method: 'POST' })).toBe(true);
        expect(wantsKeylessNotice({ ...base, headers: new Headers({ 'Content-Type': 'application/json; charset=utf-8' }) })).toBe(true);
        expect(wantsKeylessNotice({ ...base, headers: new Headers({ 'Content-Type': 'application/json', 'Content-Encoding': 'identity' }) })).toBe(true);
    });

    it.each([
        ['a keyed request', { apiKey: 'k' }],
        ['the website', { trustedUi: true }],
        ['a verified AI assistant', { verifiedAssistant: true }],
        ['an error', { status: 404 }],
        ['a 304', { status: 304 }],
        ['HEAD', { method: 'HEAD' }],
        ['a singleton (no meta; keeps its Content-Length)', { endpointType: 'singleton' }],
        ['CSV', { headers: new Headers({ 'Content-Type': 'text/csv' }) }],
        ['no content type', { headers: new Headers() }],
        ['a gzip body', { headers: new Headers({ 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }) }],
        ['a brotli body', { headers: new Headers({ 'Content-Type': 'application/json', 'Content-Encoding': 'br' }) }],
    ])('not for %s', (_label, change) => {
        expect(wantsKeylessNotice({ ...base, ...change })).toBe(false);
    });

    it('names the budget it was given, and mailto only when the request had one', () => {
        const plain = keylessNoticeFor(new URLSearchParams('per_page=1'), 0.1);
        const mailto = keylessNoticeFor(new URLSearchParams('mailto=me@example.com'), 0.1);
        expect(plain).toContain('free daily budget ($0.10)');
        expect(plain).not.toContain('mailto');
        expect(mailto).toContain("The mailto parameter doesn't raise this limit.");
        for (const n of [plain, mailto]) {
            expect(n).toContain(API_ROOT.get_a_free_key);
            expect(n).toContain(API_ROOT.llms_txt);
        }
    });
});
