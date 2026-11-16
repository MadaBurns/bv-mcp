---
ref: resolver-txt-presentation-unescape
title: Resolver consistency undoes presentation escapes in quoted TXT answers
bump: patch
plugins: []
---

### Fixed

- `check_resolver_consistency` no longer reports identical TXT records as differing when a record contains a backslash or a quote. A quote-wrapped answer is in presentation format, so its interior escapes are now undone after the outer quotes are stripped; a bare answer is left as it is. This also stops a quoted value and a bare value that differ only by a doubled backslash from reading as the same record.
