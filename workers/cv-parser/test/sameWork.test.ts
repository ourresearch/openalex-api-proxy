import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { jevPick, buildRequest, citationLine, card, resetJevPause, JEV_URL, ACCEPT_P } from '../src/sameWork';
import { matchPublication, setJevKey } from '../src/openalexMatcher';

const work = (id: string, title: string, year = 2013, type = 'article') => ({
  id: `https://openalex.org/${id}`,
  display_name: title,
  publication_year: year,
  type,
  authorships: [{ author: { display_name: 'Jason Priem' } }, { author: { display_name: 'Heather Piwowar' } }],
  primary_location: { source: { display_name: 'Nature' } },
});

/** Stub fetch: OpenAlex searches answer `results`; Jev answers `jev` (a probabilities map, an HTTP status, or a throw). */
function stub(results: any[], jev: Record<string, number> | number | 'throw') {
  const calls: { url: string; body?: any }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (u: string, init?: any) => {
    calls.push({ url: u, body: init?.body ? JSON.parse(init.body) : undefined });
    if (u === JEV_URL) {
      if (jev === 'throw') throw new Error('network down');
      if (typeof jev === 'number') return new Response('nope', { status: jev });
      return new Response(JSON.stringify({ answers: { cited_work: { type: 'choice', probabilities: jev } } }), { status: 200 });
    }
    return new Response(JSON.stringify({ results }), { status: 200 });
  }));
  return calls;
}

describe('the Jev request', () => {
  it('shows each candidate as a card with key, title, up to 6 authors, year, venue and type', () => {
    const c = card({ ...work('W1', 'A title'), authorships: Array.from({ length: 9 }, (_, i) => ({ author: { display_name: `A${i}` } })) }, 'c1');
    expect(c).toEqual({ key: 'c1', title: 'A title', authors: ['A0', 'A1', 'A2', 'A3', 'A4', 'A5'], n_authors: 9, year: 2013, venue: 'Nature', type: 'article' });
  });

  it('asks one Choice over the candidates plus none and unknown', () => {
    const req = buildRequest('Priem J (2013). A title.', 2013, [work('W1', 'A title'), work('W2', 'B title')]);
    expect(Object.keys(req.questions.cited_work.criteria)).toEqual(['c1', 'c2', 'none', 'unknown']);
    expect(req.state.citation_year).toBe(2013);
    expect(req.model).toBe('jev-1.13.0');
  });

  it('renders a CV publication as one line', () => {
    expect(citationLine({ title: 'Altmetrics in the wild.', authors: 'Priem, J., Piwowar, H.' }, 2012))
      .toBe('Priem, J., Piwowar, H. (2012) Altmetrics in the wild.');
    expect(citationLine({ title: 'Altmetrics in the wild' }, null)).toBe('Altmetrics in the wild.');
  });
});

describe('the request oxjob #1318 measured', () => {
  // Five requests #1318 sent when it measured this question (97.6% precise, 93.9% recall at p >= 0.7). Any change to the
  // instruction, the options or the card fields makes this fail: re-measure before changing them.
  const fixture: any[] = JSON.parse(readFileSync(new URL('./fixtures/samework-requests-1318.json', import.meta.url), 'utf8'));
  const asWork = (c: any) => ({
    id: c.id, display_name: c.title, publication_year: c.year, type: c.type,
    authorships: Array.from({ length: c.n_authors }, (_, i) => ({ author: { display_name: c.authors[i] ?? 'x' } })),
    primary_location: { source: c.venue == null ? null : { display_name: c.venue } },
  });

  it.each(fixture.map((f) => [f.id, f]))('rebuilds %s exactly', (_id, f) => {
    expect(buildRequest(f.citation, f.request.state.citation_year, f.candidates.map(asWork))).toEqual(f.request);
  });
});

describe('jevPick', () => {
  beforeEach(() => resetJevPause());
  afterEach(() => vi.unstubAllGlobals());
  const ws = [work('W1', 'Altmetrics in the wild'), work('W2', 'Altmetrics: a manifesto')];

  it('returns the chosen work at or above the accept line', async () => {
    stub([], { c1: 0.1, c2: 0.85, none: 0.05 });
    const r = await jevPick('x', 2013, ws, 'key');
    expect(r?.work?.id).toBe('https://openalex.org/W2');
    expect(r?.p).toBeGreaterThanOrEqual(ACCEPT_P);
  });

  it('returns no work when Jev is unsure or says none', async () => {
    stub([], { c1: 0.6, c2: 0.3, none: 0.1 });
    expect((await jevPick('x', 2013, ws, 'key'))?.work).toBeNull();
    stub([], { c1: 0.1, none: 0.9 });
    const r = await jevPick('x', 2013, ws, 'key');
    expect(r).toEqual({ work: null, p: 0.9, choice: 'none' });
  });

  it('returns null (so the caller falls back) on an HTTP error, a network error, or no key', async () => {
    stub([], 500);
    expect(await jevPick('x', 2013, ws, 'key')).toBeNull();
    resetJevPause();
    stub([], 'throw');
    expect(await jevPick('x', 2013, ws, 'key')).toBeNull();
    resetJevPause();
    const calls = stub([], { c1: 1 });
    expect(await jevPick('x', 2013, ws, undefined)).toBeNull();
    expect(calls).toEqual([]);
  });

  it('after a failure, skips Jev for a while instead of waiting on it again', async () => {
    stub([], 503);
    expect(await jevPick('x', 2013, ws, 'key')).toBeNull();
    const calls = stub([], { c1: 1 });
    expect(await jevPick('x', 2013, ws, 'key')).toBeNull();
    expect(calls).toEqual([]);
    resetJevPause();
    expect((await jevPick('x', 2013, ws, 'key'))?.work?.id).toBe('https://openalex.org/W1');
  });

  it('shows at most five candidates', async () => {
    const calls = stub([], { c1: 1 });
    await jevPick('x', 2013, Array.from({ length: 8 }, (_, i) => work(`W${i}`, `T${i}`)), 'key');
    expect(calls[0].body.state.candidates).toHaveLength(5);
  });
});

describe('matchPublication with Jev', () => {
  beforeEach(() => { setJevKey('key'); resetJevPause(); });
  afterEach(() => { vi.unstubAllGlobals(); setJevKey(undefined); });
  const pub = { title: 'Altmetrics in the wild: using social media to explore scholarly impact', year: 2012, authors: 'Priem J, Piwowar H' };
  const exact = work('W1', pub.title, 2012);

  it("takes Jev's pick from the first strategy that has one", async () => {
    stub([work('W9', 'Something else entirely'), exact], { c1: 0.02, c2: 0.97, none: 0.01 });
    const m = await matchPublication(pub, 'https://api.test');
    expect(m).toMatchObject({ matcher: 'jev', p: 0.97 });
    expect(m?.work.id).toBe('https://openalex.org/W1');
  });

  it("lets Jev's 'none' stand over a close title (no word-overlap rescue)", async () => {
    const calls = stub([exact], { c1: 0.05, none: 0.95 });
    expect(await matchPublication(pub, 'https://api.test')).toBeNull();
    // every strategy asked Jev; none fell back to bestMatch
    expect(calls.filter((c) => c.url === JEV_URL).length).toBeGreaterThan(1);
  });

  it('falls back to the word-overlap rule when Jev fails, and stops asking it for a while', async () => {
    const calls = stub([exact], 503);
    const m = await matchPublication(pub, 'https://api.test');
    expect(m).toMatchObject({ matcher: 'heuristic', p: null });
    expect(m?.work.id).toBe('https://openalex.org/W1');
    await matchPublication(pub, 'https://api.test');
    expect(calls.filter((c) => c.url === JEV_URL)).toHaveLength(1);
  });

  it('uses only the word-overlap rule when no Jev key is set', async () => {
    setJevKey(undefined);
    const calls = stub([exact], { c1: 1 });
    expect(await matchPublication(pub, 'https://api.test')).toMatchObject({ matcher: 'heuristic' });
    expect(calls.some((c) => c.url === JEV_URL)).toBe(false);
  });

  it('marks a DOI match as such and never asks Jev', async () => {
    vi.stubGlobal('fetch', vi.fn(async (u: string) => new Response(JSON.stringify(work('W1', 'X')), { status: 200 })));
    expect(await matchPublication({ title: 'X', doi: '10.1234/abc' }, 'https://api.test')).toMatchObject({ matcher: 'doi', p: null });
    expect((fetch as any).mock.calls.length).toBe(1);
  });

  it('shows Jev the five closest titles in the API order', async () => {
    const results = [
      work('W0', 'Unrelated zebrafish genetics'),
      ...Array.from({ length: 5 }, (_, i) => work(`W${i + 1}`, `Altmetrics in the wild social media scholarly impact part ${i + 1}`)),
    ];
    const calls = stub(results, { none: 1 });
    await matchPublication(pub, 'https://api.test');
    const first = calls.find((c) => c.url === JEV_URL)!;
    expect(first.body.state.candidates.map((c: any) => c.title)).toEqual(results.slice(1).map((r) => r.display_name));
  });
});
