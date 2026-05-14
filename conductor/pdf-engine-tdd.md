# TDD Plan: Enterprise PDF Engine (Playwright Integration)

## Objective
Replace the transient `npx md-to-pdf` dependency with a robust, integrated Playwright-based PDF service. This ensures faster generation, custom paged-media support (headers/footers), and reliable CI/CD verification for BrandAudit-class reports.

## Phase 1: Environment & Installation (Red)
**Test Case:** `test/pdf-engine.spec.ts`
- **Assertion:** Attempt to import `chromium` from `playwright` and call `browser.version()`.
- **Expected Failure:** `Module not found` or `Executable not found`.

**Action:**
1. Install dependencies: `npm install -D playwright`.
2. Install browser binaries: `npx playwright install chromium --with-deps`.

## Phase 2: Core PDF Service (Green)
**Test Case:** `test/pdf-engine.spec.ts` → `generatePdf()`
- **Input:** A simple HTML string: `<h1>Test Report</h1>`.
- **Assertion:** Function returns a `Buffer` where the first 4 bytes match `%PDF`.
- **Assertion:** Verify file existence after writing buffer to disk.

**Action:**
1. Create `src/lib/pdf-engine.ts`.
2. Implement `generatePdf(html: string, options: PdfOptions)` using `playwright-core`.
3. Configure `printBackground: true`, `format: 'A4'`, and `margin` defaults.

## Phase 3: Paged Media & Branding (Refactor)
**Test Case:** `test/pdf-engine.spec.ts` → `brandedReport()`
- **Assertion:** Generate a PDF with a header containing "BLACKVEIL SECURITY" and a footer with page numbers.
- **Assertion:** Use `pdf-lib` (optional) or Playwright's `headerTemplate` to verify element existence in the rendered output (via visual regression or metadata check).

**Action:**
1. Enhance `src/lib/pdf-engine.ts` to support `displayHeaderFooter: true`.
2. Inject the Obsidian-themed CSS directly into the Playwright `setContent` call.
3. Implement `headerTemplate` and `footerTemplate` using Playwright's specific template tags (`<span class="pageNumber">`, etc.).

## Phase 4: Integration with BrandAudit Corpus (Validation)
**Test Case:** `test/generate-discovery-report.spec.ts`
- **Action:** Update the script to use the new `src/lib/pdf-engine.ts` instead of shell-out to `md-to-pdf`.
- **Assertion:** Re-run the `apple.com` and `blackveilsecurity.com` reports.
- **Assertion:** Compare file size and generation speed (Playwright is typically 2x-3x faster than full `md-to-pdf` initialization).

## Verification (CI)
- Add `npx playwright install chromium --with-deps` to the GitHub Actions `test` job.
- Ensure all PDF generation tests are part of the standard `npm test` suite.
