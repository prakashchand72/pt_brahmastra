#!/usr/bin/env bash
# Build a target-specific credential wordlist.
# Usage: ./build-wordlist.sh BRAND_NAME OUTPUT_FILE
# Example: ./build-wordlist.sh kinder pentest/wordlists/target_creds.txt

BRAND="${1:-target}"
BRAND_CAP="$(echo "${BRAND:0:1}" | tr '[:lower:]' '[:upper:]')${BRAND:1}"
OUT="${2:-target_creds.txt}"

cat > "$OUT" <<EOF
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
${BRAND_CAP}@123
${BRAND_CAP}!

# Year variants
${BRAND_CAP}2024
${BRAND_CAP}2025
${BRAND_CAP}2026

# Seasonal
Summer2024
Winter2024
Spring2024
Fall2024
Summer2025
Winter2025
Spring2025

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

echo "[+] Wordlist written to $OUT ($(wc -l < "$OUT") entries)"
