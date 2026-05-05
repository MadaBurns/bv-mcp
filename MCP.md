# MCP Tool Usage Mandate: bv-context-engine

To ensure optimal performance and minimize context window usage, all coding assistants MUST adhere to the following protocols.

## 1. Tool Prioritization
- **Semantic Discovery:** ALWAYS use `codebase_search` as the primary tool for high-level "Where is X?" or "How does Y work?" questions.
- **Context Efficiency:** Do NOT use `grep` or `read_file` for broad semantic searches.

## 2. Tool Mapping
| Assistant Intent | Correct Tool |
| :--- | :--- |
| "Find where X is implemented" | `codebase_search` |
| "How do these two modules interact?" | `codebase_search` |
| "Show me all tests for Y" | `codebase_search` (with `pathFilter: "__tests__"`) |

## 3. Why this matters
Using `codebase_search` utilizes the local vector store (Ollama), which saves tokens and provides better semantic matching.
