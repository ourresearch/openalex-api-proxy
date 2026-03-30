# openalex-cv-parser

Cloudflare Worker that parses CVs/publication lists and matches publications against OpenAlex.

## How it works

1. Accepts file upload (PDF, DOCX, DOC, TXT)
2. Extracts text from the file
3. Sends text to Claude API to identify scholarly publications
4. Matches each publication against OpenAlex using multi-strategy search
5. Returns structured results (matched, unmatched, already-linked)

## Setup

```bash
npm install

# Local development (create .dev.vars from .dev.vars.example)
cp .dev.vars.example .dev.vars
# Edit .dev.vars with your Anthropic API key
npm run dev

# Deploy
wrangler secret put ANTHROPIC_API_KEY
npm run deploy
```

## API

### `POST /api/parse-cv`

**Request:** multipart/form-data
- `file` — CV file (.txt, .pdf, .docx, .doc)
- `authorId` — OpenAlex author ID (e.g., `A5086928770`)
- `authorName` — Author display name (for matching)

**Response:**
```json
{
  "totalParsed": 42,
  "matched": [
    {
      "cvPublication": { "title": "...", "doi": "10.1234/...", "year": 2023, "authors": "..." },
      "oaWork": { "id": "https://openalex.org/W...", "display_name": "...", ... },
      "alreadyLinked": false
    }
  ],
  "unmatched": [
    { "title": "...", "doi": null, "year": 2020, "authors": "..." }
  ]
}
```

## Architecture

This worker is accessed via the `openalex-api-proxy` at `api.openalex.org/cv-parse/api/parse-cv`.
The proxy forwards `/cv-parse/*` requests to this worker via a Cloudflare service binding.
