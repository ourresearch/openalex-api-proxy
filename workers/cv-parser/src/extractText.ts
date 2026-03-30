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
  // word-extractor works with Buffers in nodejs_compat mode.
  // If it fails at runtime, we provide a helpful error.
  try {
    const WordExtractor = (await import('word-extractor')).default;
    const extractor = new WordExtractor();
    const doc = await extractor.extract(buffer);
    return doc.getBody();
  } catch (err: any) {
    console.error('DOC extraction failed:', err.message);
    throw new Error(
      'Could not extract text from .doc file. Please convert to .docx or .pdf and try again.'
    );
  }
}
