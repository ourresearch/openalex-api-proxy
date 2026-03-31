/**
 * Text extraction from uploaded files.
 *
 * Supports: .txt, .pdf, .docx, .doc
 * All operations are in-memory (no filesystem access in CF Workers).
 */

import mammoth from 'mammoth';

/**
 * Extract plain text from a file buffer based on its extension.
 */
export async function extractText(
  buffer: Buffer,
  fileName: string
): Promise<string> {
  const ext = getExtension(fileName);

  switch (ext) {
    case '.txt':
      return buffer.toString('utf-8');

    case '.pdf':
      return extractPdfText(buffer);

    case '.docx':
      return extractDocxText(buffer);

    case '.doc':
      // .doc (legacy binary format) is harder in Workers.
      // Attempt extraction; fall back to error with guidance.
      return extractDocText(buffer);

    default:
      throw new Error(
        `Unsupported file type: ${ext}. Supported formats: .txt, .pdf, .docx, .doc`
      );
  }
}

function getExtension(fileName: string): string {
  const dot = fileName.lastIndexOf('.');
  if (dot === -1) return '';
  return fileName.slice(dot).toLowerCase();
}

// ─── PDF extraction via unpdf ────────────────────────────────

async function extractPdfText(buffer: Buffer): Promise<string> {
  // unpdf is designed for non-Node environments (no fs dependency)
  const { getDocumentProxy } = await import('unpdf');
  const { extractText: unpdfExtract } = await import('unpdf');

  const pdf = await getDocumentProxy(new Uint8Array(buffer));
  const { text } = await unpdfExtract(pdf, { mergePages: true });
  return text;
}

// ─── DOCX extraction via mammoth ─────────────────────────────

async function extractDocxText(buffer: Buffer): Promise<string> {
  // mammoth accepts a Buffer directly — no filesystem needed
  const result = await mammoth.extractRawText({ buffer });
  return result.value;
}

// ─── DOC extraction (legacy .doc format) ─────────────────────

async function extractDocText(buffer: Buffer): Promise<string> {
  // Strategy 1: Try mammoth — it handles some .doc files despite being a .docx library
  try {
    const result = await mammoth.extractRawText({ buffer });
    if (result.value && result.value.trim().length > 50) {
      console.log('DOC extracted via mammoth fallback');
      return result.value;
    }
  } catch {
    // mammoth couldn't handle this .doc — try next strategy
  }

  // Strategy 2: Try word-extractor (may not work in CF Workers runtime)
  try {
    const WordExtractor = (await import('word-extractor')).default;
    const extractor = new WordExtractor();
    const doc = await extractor.extract(buffer);
    const body = doc.getBody();
    if (body && body.trim().length > 0) return body;
  } catch (err: any) {
    console.error('word-extractor failed:', err.message);
  }

  // Strategy 3: Brute-force text extraction — pull readable ASCII/UTF strings from binary
  try {
    const text = extractRawStrings(buffer);
    if (text.length > 100) {
      console.log('DOC extracted via raw string extraction');
      return text;
    }
  } catch {
    // Last resort failed
  }

  throw new Error(
    'Could not extract text from .doc file. Please convert to .docx or .pdf and try again.'
  );
}

/**
 * Last-resort: pull readable text runs from a binary .doc buffer.
 * Looks for runs of printable ASCII/Latin chars (minimum 20 chars)
 * and joins them. Won't get formatting but captures body text.
 */
function extractRawStrings(buffer: Buffer): string {
  const bytes = new Uint8Array(buffer);
  const runs: string[] = [];
  let current = '';

  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    // Printable ASCII + common Latin-1 chars + newlines/tabs
    if ((b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09 || (b >= 0xc0 && b <= 0xff)) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= 20) {
        runs.push(current.trim());
      }
      current = '';
    }
  }
  if (current.length >= 20) runs.push(current.trim());

  return runs.join('\n').replace(/\n{3,}/g, '\n\n');
}
