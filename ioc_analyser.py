#!/usr/bin/env python3
"""
Phishing Email IOC Analyzer
Automatically looks for Sample_Data/sample_phishing_email.eml
"""

import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---- where is the sample? ----
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
SAMPLE = os.path.join(PROJECT_ROOT, "Sample_Data", "sample_phishing_email.eml")

print(">>> Python :", sys.version.split()[0])
print(">>> Script :", os.path.abspath(__file__))
print(">>> Sample :", SAMPLE)
print(">>> Exists :", os.path.isfile(SAMPLE))
print()

URL_RE    = re.compile(r'https?://[^\s<>"\'\)\]]+', re.I)
IPV4_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_RE  = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE   = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')


def unique(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_email(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    text = raw.decode("utf-8", errors="replace")

    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""

    headers = {}
    key = None
    for line in head.splitlines():
        if not line.strip():
            continue
        if line[0] in (" ", "\t") and key:
            headers[key] += " " + line.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            key = k.strip().lower()
            headers[key] = v.strip()

    return headers, body, text


def find_attachments(text):
    names = []
    for line in text.splitlines():
        if "filename=" in line.lower():
            part = line.split("filename=", 1)[1].strip().strip('";\'')
            if part:
                names.append(part)
    return unique(names)


def section(title, items):
    print(f"\n[{title}] ({len(items)})")
    if not items:
        print("  - none")
        return
    for item in items:
        print(f"  - {item}")


def main():
    if not os.path.isfile(SAMPLE):
        print(f"[ERROR] Sample not found: {SAMPLE}")
        print("Please create Sample_Data/sample_phishing_email.eml first.")
        return

    headers, _body, full_text = parse_email(SAMPLE)

    urls    = unique(URL_RE.findall(full_text))
    ips     = unique(IPV4_RE.findall(full_text))
    emails  = unique(EMAIL_RE.findall(full_text))
    domains = unique(DOMAIN_RE.findall(full_text))
    md5s    = unique(MD5_RE.findall(full_text))
    sha1s   = unique(SHA1_RE.findall(full_text))
    sha256s = unique(SHA256_RE.findall(full_text))
    attach  = find_attachments(full_text)

    notes = []
    from_h  = headers.get("from", "")
    reply_h = headers.get("reply-to", "")
    fe = EMAIL_RE.search(from_h)
    re_ = EMAIL_RE.search(reply_h)
    if fe and re_ and fe.group() != re_.group():
        notes.append("Sender / Reply-To mismatch (possible impersonation).")
    for h in ("authentication-results", "received-spf"):
        if "fail" in headers.get(h, "").lower():
            notes.append(f"{h} reported a failure.")
    if urls:
        notes.append(f"{len(urls)} URL(s) present - verify before clicking.")
    for d in domains:
        if d.lower().endswith((".test", ".xyz", ".top", ".click")):
            notes.append(f"Suspicious TLD in domain: {d}")
            break

    divider = "=" * 60
    print(divider)
    print(" PHISHING EMAIL IOC ANALYSIS")
    print(divider)
    print(f"File     : {os.path.basename(SAMPLE)}")
    print(f"From     : {headers.get('from', '(none)')}")
    print(f"Reply-To : {headers.get('reply-to', '(none)')}")
    print(f"Subject  : {headers.get('subject', '(none)')}")
    print(f"Date     : {headers.get('date', '(none)')}")
    print(divider)

    section("URLs", urls)
    section("Domains", domains)
    section("IP Addresses", ips)
    section("Email Addresses", emails)
    section("MD5", md5s)
    section("SHA1", sha1s)
    section("SHA256", sha256s)
    section("Attachments (filenames)", attach)

    print(f"\n[Risk Notes] ({len(notes)})")
    if not notes:
        print("  - none")
    for n in notes:
        print(f"  - {n}")
    print(divider)


if __name__ == "__main__":
    main()
