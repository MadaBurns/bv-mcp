---
description: Use when editing or creating Zod schemas, adding tool argument validation, modifying enum normalization, or deriving MCP inputSchema in this repository.
name: Zod Schema Conventions
applyTo: src/schemas/**/*.ts
---
# Zod Schema Conventions

## Source of truth

- Tool argument schemas: `src/schemas/tool-args.ts` (`TOOL_SCHEMA_MAP`)
- Tool definitions (MCP tools/list): `src/schemas/tool-definitions.ts` (`TOOLS` array, `TOOL_DEFS`)
- Shared primitives: `src/schemas/primitives.ts` (`DomainSchema`, `SessionIdSchema`, `FormatSchema`, `ProfileSchema`)
- `src/handlers/tool-schemas.ts` is a **deprecated re-export shim** — do not add new schemas there

## Key patterns

### Passthrough policy
All tool argument schemas use `.passthrough()` — preserves unknown properties for forward compatibility with different MCP client versions. Do not use `.strict()` or `.strip()`.

### Enum normalization
Use `.transform().pipe()` for case-insensitive enum matching:
```typescript
export const FormatSchema = z.string().transform(s => s.trim().toLowerCase()).pipe(z.enum(['full', 'compact']));
```
- Lowercase + trim: `FormatSchema`, `ProfileSchema`, `DmarcPolicySchema`
- Uppercase + trim: `RecordTypeSchema` (DNS record types)

### Two-layer domain validation
1. **Zod layer** (`DomainSchema`): `z.string().min(1).max(253)` — quick shape rejection
2. **Structural layer** (`lib/sanitize.ts`): `validateDomain()` + `sanitizeDomain()` for label rules, TLD checks, SSRF blocklists, punycode normalization — runs after Zod in `extractAndValidateDomain()`

Do not duplicate SSRF or structural checks in Zod schemas.

### Array element validation
Use `SafeLabelSchema` with `.regex()` refinement for array elements:
```typescript
include_providers: z.array(SafeLabelSchema.regex(/^[a-z0-9._-]+$/i)).max(15).optional()
```

### inputSchema derivation
MCP `tools/list` response derives JSON Schema from Zod via `z.toJSONSchema()` (Zod v4 built-in). Do not manually write JSON Schema — derive it from Zod.

## Adding a new tool schema

1. Define the schema in `src/schemas/tool-args.ts` using `BaseDomainArgs.extend({...}).passthrough()` for domain tools
2. Add the schema to `TOOL_SCHEMA_MAP` keyed by tool name
3. Add the tool entry to `TOOL_DEFS` in `src/schemas/tool-definitions.ts` — the `inputSchema` field is derived automatically

## Reference docs

- Canonical conventions: [CLAUDE.md](../../CLAUDE.md)
- Tool implementation: [tools.instructions.md](tools.instructions.md)
