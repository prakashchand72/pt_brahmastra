# Tracker Memory — RAG over Past Engagement Reports

## What it is

Semantic (vector) search over every Vulnerability Assessment Report in
`/Users/prakkash/shared_kali/tracker/`. Gives cross-engagement institutional memory:
"have we seen this finding / tech / target before?" — answered in milliseconds, fully
offline. It is a recall aid, never a finding source — every historical hit still needs
a live PoC on the current engagement.

## Architecture

| Component | Detail |
|---|---|
| MCP server | `tracker-memory` (registered in opencode.json) |
| Vector store | ChromaDB at `/Users/prakkash/.tracker-rag` (`chroma.sqlite3`) |
| Embeddings | ONNX all-MiniLM-L6-v2 (384-dim, fully local, cached at `~/.cache/chroma/onnx_models/`) |
| Runtime | `/Users/prakkash/rag-venv/bin/python` (Python 3.12) |
| Ingestion | `/Users/prakkash/.tracker-rag/ingest.py` |
| Index contents | `findings` collection (3825 chunks, per `#C/H/M/L/I-XX` block) + `reports` collection (2151 overviews) |

## How to use (MCP tools)

- `memory_search(query, k=5, client="", severity="")` — semantic search across all findings.
- `memory_tech_lookup(tech, k=5)` — reports where this technology/stack appeared.
- `memory_domain_lookup(domain)` — historical context for a specific target.
- `memory_stats()` — counts + store location.
- `memory_reindex()` — incremental ingest of new/modified reports (default; call after saving each report).

## Maintenance

```bash
# Full rebuild (only if store is corrupted/deleted):
~/rag-venv/bin/python /Users/prakkash/.tracker-rag/ingest.py

# Incremental (adds new/changed files only):
~/rag-venv/bin/python /Users/prakkash/.tracker-rag/ingest.py --incremental

# Direct query test (bypassing MCP):
~/rag-venv/bin/python -c "
import chromadb
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
c = chromadb.PersistentClient(path='/Users/prakkash/.tracker-rag')
col = c.get_collection('findings', embedding_function=DefaultEmbeddingFunction())
r = col.query(query_texts=['sql injection login form'], n_results=3)
print(r['documents'][0])"
```

## Notes / gotchas

- `mcp` package must stay at 1.x (`pip install "mcp==1.29.0"`) — 2.0 removed FastMCP.
- Client reports are sensitive: the store is fully local, never ship it anywhere.
- Only ~570/2151 reports carry parsed technology lists (the rest are scaffolds) — that's expected; tech lookup improves as real reports accumulate.
- Re-index is fingerprint-based (sha256) so it's cheap and idempotent.
