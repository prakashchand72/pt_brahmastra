#!/usr/bin/env bash
set -euo pipefail
# Build a target-specific credential wordlist.
# Usage: ./build-wordlist.sh BRAND_NAME OUTPUT_FILE
# Example: ./build-wordlist.sh kinder pentest/wordlists/target_creds.txt

BRAND="${1:-target}"
BRAND_CAP="$(echo "${BRAND:0:1}" | tr '[:lower:]' '[:upper:]')${BRAND:1}"
OUT="${2:-target_creds.txt}"

YEAR="$(date +%Y)"

mkdir -p "$(dirname "$OUT")"

RAW="$(mktemp)"
trap 'rm -f "$RAW"' EXIT

cat > "$RAW" <<EOF
# Admin defaults
admin
Admin
administrator
${BRAND}
${BRAND_CAP}

# Brand + numbers
${BRAND}123
${BRAND_CAP}123
${BRAND_CAP}1234
${BRAND}@123
${BRAND_CAP}@123
${BRAND_CAP}!

# Common weak passwords
Admin@123
admin@123
Admin123!
password
Password1
Password123
P@ssw0rd
Passw0rd
Welcome1
welcome1

# Generic
123456
1234567890
qwerty123
letmein
changeme
test123
Test123
guest
Guest123

# Platform-specific (CMS, webmail, cPanel)
modx
Modx123
cpanel
cPanel123
EOF

# Year variants — generated dynamically (last year, current, next)
{
    echo "# Year variants"
    for y in $((YEAR - 1)) "$YEAR" $((YEAR + 1)); do
        echo "${BRAND_CAP}${y}"
    done

    echo "# Seasonal (current and next year)"
    for y in "$YEAR" $((YEAR + 1)); do
        for s in Summer Winter Spring Fall; do
            echo "${s}${y}"
        done
    done
} >> "$RAW"

# Strip comment/blank lines and de-duplicate (order-preserving)
grep -v '^#' "$RAW" | grep -v '^$' | awk '!seen[$0]++' > "$OUT"

echo "[+] Wordlist written to $OUT ($(wc -l < "$OUT") entries)"
