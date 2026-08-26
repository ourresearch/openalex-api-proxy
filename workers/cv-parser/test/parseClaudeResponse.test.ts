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

  it('throws on valid JSON that is not an array', () => {
    expect(() => parsePublicationsJson('{"title": "not an array"}')).toThrow(
      'Failed to parse publications from CV'
    );
  });
});
