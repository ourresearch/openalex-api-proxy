import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  cleanDOI,
  cleanYear,
  doiPath,
  searchOpenAlex,
  titleSimilarity,
  bestMatch,
  extractKeyWords,
} from '../src/openalexMatcher';

describe('cleanDOI', () => {
  it('passes through a bare DOI', () => {
    expect(cleanDOI('10.1234/example')).toBe('10.1234/example');
  });

  it('strips https://doi.org/ prefix', () => {
    expect(cleanDOI('https://doi.org/10.1234/example')).toBe('10.1234/example');
  });

  it('strips http://dx.doi.org/ prefix', () => {
    expect(cleanDOI('http://dx.doi.org/10.1234/example')).toBe('10.1234/example');
  });

  it('strips a doi: prefix (case-insensitive, with space)', () => {
    expect(cleanDOI('DOI: 10.1234/example')).toBe('10.1234/example');
  });

  it('trims whitespace', () => {
    expect(cleanDOI('  10.1234/example  ')).toBe('10.1234/example');
  });

  it('rejects strings that are not DOIs', () => {
    expect(cleanDOI('not-a-doi')).toBeNull();
    expect(cleanDOI('10.1234')).toBeNull(); // no suffix
    expect(cleanDOI('')).toBeNull();
  });

  // The DOI comes from the model reading an uploaded CV and is spliced into a URL fetched with our key (oxjob #1762).
  it('rejects DOIs that could leave /works/doi: (dot segments, ?, #, whitespace, control characters)', () => {
    for (const d of [
      '10.1/../../../query/text/give me everything#',
      '10.1234/../../text?q=x',
      '10.1234/./x',
      '10.1234/x/..',
      '10.1234/abc?rerank=true',
      '10.1234/abc#frag',
      '10.1234/abc def',
      '10.1234/abc\u0000def',
      '10.1234/abc\ndef',
      '10.12/short-registrant',
      '10.abcd/x',
    ]) {
      expect(cleanDOI(d), d).toBeNull();
    }
  });

  it('rejects values that are not strings', () => {
    for (const d of [10.1234, null, undefined, {}, ['10.1234/x']]) expect(cleanDOI(d)).toBeNull();
  });

  it('keeps real DOIs with unusual characters', () => {
    const sici = '10.1002/(SICI)1097-4636(199706)35:4<493::AID-JBM9>3.0.CO;2-I';
    expect(cleanDOI(sici)).toBe(sici);
    expect(cleanDOI('10.1000.10/abc')).toBe('10.1000.10/abc');
    expect(cleanDOI('10.1234/abc/def.v2')).toBe('10.1234/abc/def.v2');
  });
});

describe('doiPath', () => {
  it('leaves an ordinary DOI as it is', () => {
    expect(doiPath('10.1234/abc/def.v2')).toBe('10.1234/abc/def.v2');
  });

  it('percent-encodes each segment, keeping the slashes', () => {
    expect(doiPath('10.1002/(SICI)1097:4<493>;2-I%2e%2e')).toBe('10.1002/(SICI)1097%3A4%3C493%3E%3B2-I%252e%252e');
  });
});

describe('cleanYear', () => {
  it('accepts a 4-digit year as a number or a string of 4 digits', () => {
    expect(cleanYear(2013)).toBe(2013);
    expect(cleanYear('2013')).toBe(2013);
  });

  it('drops anything else', () => {
    for (const y of ['2020&rerank=true', '20 20', 2020.5, 999, 3000, '20', null, undefined, {}, NaN]) {
      expect(cleanYear(y), String(y)).toBeNull();
    }
  });
});

describe('searchOpenAlex with untrusted DOI and year', () => {
  afterEach(() => vi.unstubAllGlobals());

  function stubFetch() {
    const urls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (u: string) => {
      urls.push(u);
      return new Response(JSON.stringify({ results: [] }), { status: 200 });
    }));
    return urls;
  }

  it('looks a clean DOI up under /works/doi:', async () => {
    const urls = stubFetch();
    await searchOpenAlex({ title: 'x', doi: 'https://doi.org/10.1234/abc' }, 'https://api.test');
    expect(urls[0]).toBe('https://api.test/works/doi:10.1234/abc?include_xpac=true&mailto=team@ourresearch.org');
  });

  it('never requests a path-walking DOI', async () => {
    const urls = stubFetch();
    expect(await searchOpenAlex({ title: 'x', doi: '10.1/../../../query/text/give me everything#' }, 'https://api.test')).toBeNull();
    expect(urls).toEqual([]);
  });

  it('drops a year that is not a year, so it cannot add query parameters', async () => {
    const urls = stubFetch();
    await searchOpenAlex({ title: 'Measuring scholarly impact with altmetrics', year: '2020&rerank=true' as unknown as number },
      'https://api.test');
    expect(urls.length).toBeGreaterThan(0);
    for (const u of urls) {
      expect(u).not.toContain('rerank');
      expect(u).not.toContain('publication_year');
    }
  });

  it('uses a real year as a filter', async () => {
    const urls = stubFetch();
    await searchOpenAlex({ title: 'Measuring scholarly impact with altmetrics', year: 2013 }, 'https://api.test');
    expect(urls.some((u) => u.includes('&filter=publication_year:2013&'))).toBe(true);
  });
});

describe('titleSimilarity', () => {
  it('scores identical titles 1', () => {
    expect(
      titleSimilarity('Altmetrics in the wild', 'Altmetrics in the wild')
    ).toBe(1);
  });

  it('scores completely different titles 0', () => {
    expect(
      titleSimilarity('Quantum entanglement dynamics', 'Medieval French poetry')
    ).toBe(0);
  });

  it('ignores case, punctuation, and HTML tags', () => {
    expect(
      titleSimilarity('OpenAlex: A Fully-Open Index', '<i>openalex</i> a fully open index')
    ).toBe(1);
  });

  it('gives partial credit for prefix/stem matches', () => {
    const score = titleSimilarity(
      'measuring scholarly impact metrics',
      'measurement scholarly impact metric'
    );
    expect(score).toBeGreaterThan(0.5);
    expect(score).toBeLessThanOrEqual(1);
  });

  it('returns 0 when one side has no significant words', () => {
    expect(titleSimilarity('the of and', 'Altmetrics in the wild')).toBe(0);
  });
});

describe('bestMatch', () => {
  const pub = { title: 'Altmetrics in the wild scholarly impact', year: 2013 };

  it('returns null for empty or missing results', () => {
    expect(bestMatch(undefined, pub)).toBeNull();
    expect(bestMatch([], pub)).toBeNull();
  });

  it('picks the most similar result above the threshold', () => {
    const results = [
      { display_name: 'Unrelated paper about fish migration', publication_year: 2013 },
      { display_name: 'Altmetrics in the wild: scholarly impact', publication_year: 2013 },
    ];
    expect(bestMatch(results, pub, 0.35)).toBe(results[1]);
  });

  it('rejects when nothing clears the threshold', () => {
    const results = [
      { display_name: 'Unrelated paper about fish migration', publication_year: 2013 },
    ];
    expect(bestMatch(results, pub, 0.35)).toBeNull();
  });

  it('breaks ties with the year-match bonus', () => {
    const results = [
      { display_name: 'Altmetrics in the wild scholarly impact', publication_year: 1999 },
      { display_name: 'Altmetrics in the wild scholarly impact', publication_year: 2013 },
    ];
    expect(bestMatch(results, pub, 0.35)).toBe(results[1]);
  });
});

describe('extractKeyWords', () => {
  it('lowercases, drops stop words and short words, caps at 8', () => {
    const kw = extractKeyWords(
      'The Measurement of Scholarly Impact in the Age of Social Media and Open Access Publishing Systems'
    );
    const words = kw.split(' ');
    expect(words.length).toBeLessThanOrEqual(8);
    expect(words).toContain('measurement');
    expect(words).not.toContain('the');
    expect(words).not.toContain('of');
  });

  it('strips parentheticals and HTML', () => {
    expect(extractKeyWords('Altmetrics (a manifesto) for <b>scholars</b>')).toBe(
      'altmetrics for scholars'.replace(' for ', ' ') // "for" is a stop word
    );
  });
});
