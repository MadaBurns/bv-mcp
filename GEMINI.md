# Project Architectural Mandates

## 1. Codebase Exploration (MCP)
- **Primary Tool:** ALWAYS use `codebase_search` (from `bv-context-engine`) for semantic queries, architectural mapping, and finding symbols.
- **Context Management:** Do not perform exhaustive `grep` or `ls -R` calls. Use the semantic search tool to minimize context window bloat.
- **Search Scope:** This project is indexed in the `bv-context-engine` vector store.

## 2. Technical Standards
- **Standard Stack:** Adhere to the established patterns in this repository for testing, typing, and architecture.
