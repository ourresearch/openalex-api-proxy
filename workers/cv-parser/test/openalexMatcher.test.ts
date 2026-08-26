import { describe, it, expect } from 'vitest';
import {
  cleanDOI,
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
