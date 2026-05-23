#!/usr/bin/env bash
# Professional-grade PDF builder for the CSC package.
#
# Pipeline: pandoc (.md → HTML fragments) → assemble single master HTML
# (cover + TOC + 01 + 02 + 03 with page breaks) → Chrome headless --print-to-pdf
# → one bundled PDF with consistent page numbers across the whole document.
#
# Also produces per-section PDFs as a side product (for emailing one section
# without the rest).
#
# Output:
#   build/pdf/00-cover.pdf
#   build/pdf/01-exec-summary.pdf
#   build/pdf/02-walkthrough.pdf
#   build/pdf/03-provenance.pdf
#   build/pdf/bv-csc-package.pdf          ← the recommended attachment
#
# Usage:
#   ./build-pdf.sh              # full build
#   ./build-pdf.sh --clean      # rm -rf build/pdf
#   ./build-pdf.sh --bundle-only # skip per-section PDFs

set -euo pipefail
cd "$(dirname "$0")"

OUT="./build/pdf"

case "${1:-}" in
--clean)
	rm -rf "$OUT"
	echo "Cleaned $OUT"
	exit 0
	;;
--help | -h)
	grep '^#' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
esac

BUNDLE_ONLY=0
for arg in "$@"; do
	[[ "$arg" == "--bundle-only" ]] && BUNDLE_ONLY=1
done

# --- detect Chrome ---
CHROME=""
for app in \
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
	"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
	"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
	"/Applications/Chromium.app/Contents/MacOS/Chromium"; do
	if [[ -x "$app" ]]; then
		CHROME="$app"
		break
	fi
done
[[ -z "$CHROME" ]] && {
	echo "No Chromium-family browser found." >&2
	exit 1
}
command -v pandoc >/dev/null || {
	echo "pandoc not found — brew install pandoc" >&2
	exit 1
}

echo "Chrome:    $CHROME"
echo "pandoc:    $(pandoc --version | head -1)"
echo

mkdir -p "$OUT/html"
cp pdf-style.css "$OUT/html/pdf-style.css"

# --- helpers ---

# Render a markdown file to a body-fragment HTML (no <html><head>, just content).
render_fragment() {
	local src="$1"
	local out="$2"
	pandoc "$src" \
		--from gfm+yaml_metadata_block \
		--to html5 \
		-o "$out"
}

# Wrap a body-fragment HTML inside a complete document with our stylesheet.
wrap_doc() {
	local body_file="$1"
	local out="$2"
	local title="${3:-BlackVeil DNS — DomainSec Complement}"
	{
		cat <<-EOF
			<!doctype html>
			<html lang="en">
			<head>
			<meta charset="utf-8">
			<title>$title</title>
			<link rel="stylesheet" href="pdf-style.css">
			</head>
			<body>
		EOF
		cat "$body_file"
		cat <<-EOF
			</body>
			</html>
		EOF
	} >"$out"
}

print_pdf() {
	local html="$1" pdf="$2"
	local base; base="$(pwd)"
	"$CHROME" \
		--headless=new \
		--disable-gpu \
		--no-sandbox \
		--no-pdf-header-footer \
		--print-to-pdf="$base/$pdf" \
		--virtual-time-budget=10000 \
		"file://$base/$html" 2>/dev/null
	if [[ -f "$pdf" ]]; then
		printf "  → %s (%s)\n" "$pdf" "$(du -h "$pdf" | awk '{print $1}')"
	else
		echo "  ✗ FAILED: $pdf" >&2
		return 1
	fi
}

# --- 1. Render each section to a body fragment ---
echo "Rendering markdown to HTML fragments..."
render_fragment 01-exec-summary.md "$OUT/html/01.body.html"
render_fragment 02-walkthrough.md "$OUT/html/02.body.html"
render_fragment 03-provenance.md "$OUT/html/03.body.html"
echo

# --- 2. Assemble master HTML with cover + TOC + sections + page breaks ---
echo "Assembling master HTML..."
{
	cat <<-EOF
		<!doctype html>
		<html lang="en">
		<head>
		<meta charset="utf-8">
		<title>BlackVeil DNS — DomainSec Complement (full package)</title>
		<link rel="stylesheet" href="pdf-style.css">
		</head>
		<body>
	EOF
	cat cover.html
	echo '<div class="section-break"></div>'
	cat "$OUT/html/01.body.html"
	echo '<div class="section-break"></div>'
	cat "$OUT/html/02.body.html"
	echo '<div class="section-break"></div>'
	cat "$OUT/html/03.body.html"
	cat <<-EOF
		</body>
		</html>
	EOF
} >"$OUT/html/master.html"
echo "  → $OUT/html/master.html"
echo

# --- 3. Print the master to one PDF ---
echo "Printing master to bv-csc-package.pdf..."
print_pdf "$OUT/html/master.html" "$OUT/bv-csc-package.pdf"
echo

# --- 4. Per-section PDFs (side product, useful for forwarding) ---
if [[ "$BUNDLE_ONLY" -eq 0 ]]; then
	echo "Printing per-section PDFs..."
	# Cover gets its own standalone document
	wrap_doc cover.html "$OUT/html/00-cover.full.html" "BlackVeil DNS — Cover"
	wrap_doc "$OUT/html/01.body.html" "$OUT/html/01-exec-summary.full.html" "BlackVeil DNS — Exec Summary"
	wrap_doc "$OUT/html/02.body.html" "$OUT/html/02-walkthrough.full.html" "BlackVeil DNS — Walkthrough"
	wrap_doc "$OUT/html/03.body.html" "$OUT/html/03-provenance.full.html" "BlackVeil DNS — Provenance"

	print_pdf "$OUT/html/00-cover.full.html" "$OUT/00-cover.pdf"
	print_pdf "$OUT/html/01-exec-summary.full.html" "$OUT/01-exec-summary.pdf"
	print_pdf "$OUT/html/02-walkthrough.full.html" "$OUT/02-walkthrough.pdf"
	print_pdf "$OUT/html/03-provenance.full.html" "$OUT/03-provenance.pdf"
fi

echo
echo "Done. Page count of bundled PDF:"
pdfinfo "$OUT/bv-csc-package.pdf" 2>/dev/null | awk -F': +' '/^Pages:/ {print "  " $2 " pages"}'
echo
ls -la "$OUT"/*.pdf 2>/dev/null
