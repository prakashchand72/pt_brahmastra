#!/usr/bin/env python3
"""
saml_decode.py — Decode a SAML AuthnRequest/Response from an ADFS/HTTP-Redirect URL.

Purpose:
    When a Service Provider (SP) redirects the browser to the IdP (e.g. ADFS),
    it passes a `SAMLRequest` query parameter that is:
        1. DEFLATE-compressed (raw DEFLATE, zlib with -MAX_WBITS = -15),
        2. encoded with STANDARD base64 (not base64url), AND
        3. URL-encoded (%-encoded) for transport in the query string
    This script reverses that so you can read the SP's SAML metadata
    (AssertionConsumerServiceURL, Issuer, Destination, NameIDPolicy, etc.).

Usage:
    python3 saml_decode.py "<SAMLRequest value>"
    # or pipe it:
    echo "<SAMLRequest value>" | python3 saml_decode.py

Example:
    curl -sk "https://api.bcf.ch/login" -D - -o /dev/null \
        | grep -i '^location:' \
        | python3 saml_decode.py --from-location-header
"""
import sys
import base64
import binascii
import zlib
import urllib.parse
import re


def decode_saml(b64_value: str) -> str:
    # 1. URL-decode (SAMLRequest may be %-encoded inside the Location header)
    val = urllib.parse.unquote(b64_value.strip())
    val = re.sub(r'\s+', '', val)  # tolerate pasted line breaks
    # 2. base64 -> raw bytes (SAML uses standard base64; tolerate url-safe
    #    alphabet and missing padding anyway)
    val = val.replace('-', '+').replace('_', '/')
    val += '=' * (-len(val) % 4)
    try:
        raw = base64.b64decode(val, validate=True)
    except binascii.Error:
        print("[!] Input is not valid base64 — paste the raw SAMLRequest/SAMLResponse value",
              file=sys.stderr)
        sys.exit(1)
    # 3. DEFLATE decompress: try raw deflate (wbits=-15) then zlib (wbits=15)
    for wbits in (-15, 15):
        try:
            return zlib.decompress(raw, wbits).decode('utf-8', 'replace')
        except Exception:
            continue
    # 4. Not compressed — return as-is (some IdPs send plain base64)
    return raw.decode('utf-8', 'replace')


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--from-location-header':
        # Read a raw `curl -D -` header dump from stdin and pull the SAMLRequest
        data = sys.stdin.read()
        m = re.search(r'[?&]SAML(?:Request|Response)=([^&\s"]+)', data, re.I)
        if not m:
            print("[!] SAMLRequest/SAMLResponse not found in input", file=sys.stderr)
            sys.exit(1)
        value = m.group(1)
    elif len(sys.argv) > 1:
        value = sys.argv[1]
    else:
        value = sys.stdin.read()

    xml = decode_saml(value)
    print(xml)


if __name__ == '__main__':
    main()
