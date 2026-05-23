#!/usr/bin/env bash
# Build the CSC partnership package (PDFs + standalone HTML).
#
# Outputs go to ./build/ alongside this script. The cover email
# (00-cover-email.md) is intentionally NOT converted — it's the body
# text for the actual send, not an attachment.
#
# Usage:
#   ./build.sh              # build everything
#   ./build.sh --html-only  # skip the PDF step (no LaTeX required)
#   ./build.sh --clean      # rm -rf ./build then exit
#
# Requirements:
#   pandoc >= 3.0           (decisions D7: pandoc v3.9.0.2 verified)
#   For PDFs: a LaTeX engine — xelatex (MacTeX) preferred, lualatex
#   or pdflatex acceptable. Falls back to wkhtmltopdf if no TeX engine
#   is found. If none of those exist, prints install hint and exits 1.

set -euo pipefail

cd "$(dirname "$0")"

BUILD_DIR="./build"
HTML_ONLY=0

for arg in "$@"; do
	case "$arg" in
	--clean)
		rm -rf "$BUILD_DIR"
		echo "Cleaned $BUILD_DIR"
		exit 0
		;;
	--html-only) HTML_ONLY=1 ;;
	-h | --help)
		grep '^#' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "Unknown arg: $arg" >&2
		exit 1
		;;
	esac
done

command -v pandoc >/dev/null 2>&1 || {
	echo "pandoc not found — install via 'brew install pandoc'" >&2
	exit 1
}

mkdir -p "$BUILD_DIR"

# Detect a PDF engine
PDF_ENGINE=""
if [[ "$HTML_ONLY" -eq 0 ]]; then
	for engine in xelatex lualatex pdflatex wkhtmltopdf; do
		if command -v "$engine" >/dev/null 2>&1; then
			PDF_ENGINE="$engine"
			break
		fi
	done
	if [[ -z "$PDF_ENGINE" ]]; then
		cat >&2 <<-'EOF'
			No PDF engine found (xelatex / lualatex / pdflatex / wkhtmltopdf).

			Three options:
			  1. brew install --cask mactex-no-gui    (≈4 GB, gives xelatex — typeset quality)
			  2. brew install --cask wkhtmltopdf      (≈100 MB, simpler — HTML→PDF)
			  3. ./build.sh --html-only && open build/*.html, then File → Export to PDF
			     (browser print is the cleanest path for partner-facing PDFs)
		EOF
		exit 1
	fi
	echo "PDF engine: $PDF_ENGINE"
fi

build_one() {
	local src="$1"
	local stem
	stem="$(basename "$src" .md)"

	# HTML build — always
	pandoc "$src" \
		--from gfm+yaml_metadata_block \
		--to html5 \
		--standalone \
		--metadata=lang:en \
		--css="data:text/css;base64,$(printf '%s' "$EMBEDDED_CSS" | base64)" \
		-o "$BUILD_DIR/$stem.html"
	echo "  → $BUILD_DIR/$stem.html"

	# PDF build — optional
	if [[ -n "$PDF_ENGINE" ]]; then
		local engine_args=(--pdf-engine="$PDF_ENGINE")
		# TeX engines need geometry tweaks; wkhtmltopdf doesn't
		case "$PDF_ENGINE" in
		xelatex | lualatex | pdflatex)
			engine_args+=(-V geometry:margin=0.9in -V fontsize=10pt -V colorlinks=true)
			;;
		esac
		pandoc "$src" \
			--from gfm+yaml_metadata_block \
			"${engine_args[@]}" \
			-o "$BUILD_DIR/$stem.pdf"
		echo "  → $BUILD_DIR/$stem.pdf"
	fi
}

# Standalone-HTML CSS — minimal, neutral, print-friendly.
# Inlined so the build is single-file and the HTML output is portable.
EMBEDDED_CSS='
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
       max-width: 820px; margin: 2em auto; padding: 0 1em; line-height: 1.5; color: #222; }
h1, h2, h3 { line-height: 1.2; }
h1 { border-bottom: 2px solid #222; padding-bottom: 0.3em; }
h2 { margin-top: 2em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }
code { background: #f4f4f4; padding: 0.1em 0.3em; border-radius: 3px; font-size: 0.92em; }
pre code { background: transparent; padding: 0; }
pre { background: #f4f4f4; padding: 1em; border-radius: 4px; overflow-x: auto; }
table { border-collapse: collapse; margin: 1em 0; width: 100%; font-size: 0.94em; }
th, td { border: 1px solid #ccc; padding: 0.4em 0.6em; text-align: left; vertical-align: top; }
th { background: #f4f4f4; }
blockquote { border-left: 3px solid #888; margin: 0; padding: 0.4em 1em; color: #555; background: #fafafa; }
hr { border: none; border-top: 1px solid #ccc; margin: 2em 0; }
'

echo "Building CSC package → $BUILD_DIR/"
for src in 01-exec-summary.md 02-walkthrough.md 03-provenance.md; do
	if [[ ! -f "$src" ]]; then
		echo "Missing source: $src" >&2
		exit 1
	fi
	echo "Building $src"
	build_one "$src"
done

# Cover email: keep markdown only — it's email body, not an attachment.
# Render an HTML preview for convenience; do NOT generate a PDF.
if [[ -f 00-cover-email.md ]]; then
	echo "Rendering 00-cover-email.md → preview HTML (not for attaching)"
	pandoc 00-cover-email.md \
		--from gfm+yaml_metadata_block \
		--to html5 \
		--standalone \
		--metadata=lang:en \
		--metadata=title:"Cover email (preview)" \
		--css="data:text/css;base64,$(printf '%s' "$EMBEDDED_CSS" | base64)" \
		-o "$BUILD_DIR/00-cover-email-preview.html"
	echo "  → $BUILD_DIR/00-cover-email-preview.html"
fi

echo
echo "Done. Contents of $BUILD_DIR:"
ls -la "$BUILD_DIR"
