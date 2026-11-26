---
ref: call-time-errors-compact-scan
title: Self-correcting call errors and a smaller compact scan_domain payload
bump: minor
plugins: []
---

### Changed

- `scan_domain` with `format: "compact"` now trims `structuredContent` as well as the text, for hosts that give the model the structured payload instead of the text. `webPosture` becomes a per-category summary (category, passed, score, and the title and severity of each non-info finding). Info findings keep `category`, `title` and `severity` and lose `detail`; none are removed, because the text report omits info findings in every format. Scores, grade, `categoryScores`, `findingCounts`, `checkStatuses`, every non-info finding and all other keys are unchanged. A new `compactDetailOmitted` field says detail was left out and that `format: "full"` returns it. `format: "full"`, callers that send no client type (including the internal service-binding door) and the `buildStructuredScanResult` export are unchanged.
- `explain_finding` called with a `status` that is present but not accepted now returns `Invalid status: "<value>". Use one of: pass, fail, warning, critical, high, medium, low, info.` instead of claiming both parameters are missing. The missing-parameters message is unchanged when a parameter is really absent.
- A URL, email address or `host:port` passed as `domain` is still rejected, now with `Pass a bare hostname such as example.com, without scheme, path, port or user part` instead of a label-syntax error. No input that was rejected is now accepted, and no accepted input is rejected.
- An unknown tool name now ends with `Did you mean: <name>?` when one to three public tools are close (small edit distance, or the same name with a missing or extra `check_` prefix). Suggestions come only from the tools the public `tools/list` shows, never from internal-only tools, and the message still begins `Unknown tool:`.
