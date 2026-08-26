import { describe, it, expect } from 'vitest';
import { extractText } from '../src/extractText';

describe('extractText', () => {
  it('returns .txt content as utf-8', async () => {
    const text = 'Publications:\n1. Priem, J. (2013). Altmetrics in the wild.';
    expect(await extractText(Buffer.from(text, 'utf-8'), 'cv.txt')).toBe(text);
  });

  it('is case-insensitive about the extension', async () => {
    expect(await extractText(Buffer.from('hello'), 'CV.TXT')).toBe('hello');
  });

  it('throws a helpful error for unsupported extensions', async () => {
    await expect(extractText(Buffer.from('x'), 'cv.rtf')).rejects.toThrow(
      /Unsupported file type: \.rtf/
    );
  });

  it('throws for files with no extension', async () => {
    await expect(extractText(Buffer.from('x'), 'cv')).rejects.toThrow(
      /Unsupported file type/
    );
  });

  describe('.doc fallback (raw string extraction)', () => {
    it('pulls readable text runs out of a binary buffer', async () => {
      // Fake "binary .doc": printable runs (>=20 chars) separated by binary junk.
      const runs = [
        'Curriculum Vitae of Jason Priem, researcher.',
        'Altmetrics in the wild: using social media to explore scholarly impact.',
        'OpenAlex: a fully-open index of scholarly works and authors.',
      ];
      const junk = Buffer.from([0x00, 0x01, 0x02, 0xd0, 0xcf, 0x11, 0xe0, 0x03]);
      const buffer = Buffer.concat(
        runs.flatMap((r) => [junk, Buffer.from(r, 'latin1')]).concat([junk])
      );

      const text = await extractText(buffer, 'cv.doc');
      for (const run of runs) {
        expect(text).toContain(run);
      }
    });

    it('throws with conversion guidance when nothing is extractable', async () => {
      // All binary junk, no printable runs long enough to keep.
      const buffer = Buffer.alloc(512, 0x01);
      await expect(extractText(buffer, 'cv.doc')).rejects.toThrow(
        /convert to \.docx or \.pdf/
      );
    });
  });
});
