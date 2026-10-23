import { describe, it, expect } from 'vitest';
import { parsePublicationsJson } from '../src/parseClaudeResponse';

const PUBS = [
  { title: 'Altmetrics in the wild', doi: '10.1234/test', year: 2013, authors: 'Priem, J.' },
  { title: 'OpenAlex: A fully-open index', doi: null, year: 2022, authors: null },
];

describe('parsePublicationsJson', () => {
  it('parses a plain JSON array', () => {
    expect(parsePublicationsJson(JSON.stringify(PUBS))).toEqual(PUBS);
  });

  it('parses an empty array', () => {
    expect(parsePublicationsJson('[]')).toEqual([]);
  });

  it('strips ```json code fences', () => {
    const content = '```json\n' + JSON.stringify(PUBS) + '\n```';
    expect(parsePublicationsJson(content)).toEqual(PUBS);
  });

  it('strips bare ``` code fences', () => {
    const content = '```\n' + JSON.stringify(PUBS) + '\n```';
    expect(parsePublicationsJson(content)).toEqual(PUBS);
  });

  it('tolerates surrounding whitespace', () => {
    expect(parsePublicationsJson('  \n' + JSON.stringify(PUBS) + '\n  ')).toEqual(PUBS);
  });

  it('throws on invalid JSON', () => {
    expect(() => parsePublicationsJson('here are your publications!')).toThrow(
      'Failed to parse publications from CV'
    );
  });

  // The model read an uploaded CV, so every field's type is checked (oxjob #1762).
  it('keeps only well-typed fields: a year must be a 4-digit year, a DOI a string', () => {
    const content = JSON.stringify([
      { title: 'A', doi: 10.1234, year: '2020&rerank=true', authors: ['x'] },
      { title: 'B', doi: '10.1234/b', year: '2013', authors: 'Priem, J.' },
    ]);
    expect(parsePublicationsJson(content)).toEqual([
      { title: 'A', doi: null, year: null, authors: null },
      { title: 'B', doi: '10.1234/b', year: 2013, authors: 'Priem, J.' },
    ]);
  });

  it('drops elements that are not objects with a title or DOI string; keeps a DOI-only one', () => {
    const content = JSON.stringify([null, 7, 'title', ['x'], { year: 2013 }, { title: 5 }, { doi: '10.1234/c' }]);
    expect(parsePublicationsJson(content)).toEqual([{ title: '', doi: '10.1234/c', year: null, authors: null }]);
  });

  it('throws on valid JSON that is not an array', () => {
    expect(() => parsePublicationsJson('{"title": "not an array"}')).toThrow(
      'Failed to parse publications from CV'
    );
  });
});
