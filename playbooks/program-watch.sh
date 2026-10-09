#!/bin/bash
# program-watch.sh — watch bug-bounty program scope pages, alert on changes.
# Fresh scope = first-48-hour advantage. Run via cron; when scope changes,
# launch Phase 1–3 on the new assets immediately.
#
# Watchlist format (~/.brahmastra/watchlist.txt), one per line:
#   <name> <url>
#   acme   https://hackerone.com/acme/policy?type=team
#   globo  https://bugcrowd.com/globo
# Lines starting with # are ignored.
#
# Notes:
# - Works on any URL. JS-heavy pages (some Bugcrowd/Intigriti) may need the
#   playwright fallback: fetch manually once, save into ~/.brahmastra/watch/.
# - macOS-safe (shasum, BSD sed). No dependencies beyond curl.
#
# Cron example (check every 6 hours at a jittered minute):
#   23 */6 * * *  ~/.hermes/skills/pt_brahmastra/playbooks/program-watch.sh >> ~/.brahmastra/watch.log 2>&1

set -euo pipefail

DIR="${WATCH_DIR:-$HOME/.brahmastra/watch}"
LIST="${WATCHLIST:-$HOME/.brahmastra/watchlist.txt}"
mkdir -p "$DIR"

[ -f "$LIST" ] || { echo "[setup] create $LIST — format: <name> <url> per line"; exit 1; }

# Extract scope-ish tokens (domains, wildcards) for the change diff.
scope_tokens() {
  grep -oiE '(\*\.)?[a-z0-9][a-z0-9.-]*\.(com|net|org|io|dev|app|co|cloud|gg|sh)([/?][a-z0-9./_-]*)?' "$1" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' | sort -u
}

while read -r name url; do
  [ -z "${name:-}" ] && continue
  case "$name" in \#*) continue ;; esac

  snap="$DIR/$name.html"
  meta="$DIR/$name.meta"
  tmp=$(mktemp); tmpn=$(mktemp)

  if curl -skL --max-time 30 -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" "$url" -o "$tmp"; then
    # Normalize away volatile junk (csrf tokens, timestamps) so only real
    # content changes trigger.
    sed -E 's/(csrf|authenticity|nonce|token|timestamp|updated[_-]?at|cache[_-]?buster)[^<"]{0,120}//gi' "$tmp" \
      | tr -d '[:space:]' > "$tmpn"
    new_hash=$(shasum -a 256 "$tmpn" | cut -d' ' -f1)
    old_hash=$(cat "$meta" 2>/dev/null || echo "none")

    if [ "$new_hash" != "$old_hash" ]; then
      if [ ! -f "$snap" ]; then
        echo "[BASELINE] $name — first snapshot saved ($url)"
      else
        echo ""
        echo "================ SCOPE CHANGE: $name ================"
        echo "URL: $url"
        echo "--- scope diff (< old, > new) ---"
        diff <(scope_tokens "$snap") <(scope_tokens "$tmp") \
          | grep -E '^[<>]' | head -40 || echo "(page changed but no domain-scope diff — check policy text/bounty table)"
        echo ""
        echo ">>> ACTION: triage the new/changed assets — launch Phase 1–3 NOW."
        echo ">>> First 48 hours on fresh scope is where the bugs are."
      fi
      cp "$tmp" "$snap"
      echo "$new_hash" > "$meta"
    else
      echo "[same] $name"
    fi
  else
    echo "[error] $name — fetch failed ($url)"
  fi

  rm -f "$tmp" "$tmpn"
done < "$LIST"
