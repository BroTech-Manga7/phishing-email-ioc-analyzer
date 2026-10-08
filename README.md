# Phishing Email IOC Analyzer

A Python tool that performs static analysis on `.eml` files and extracts
Indicators of Compromise (IOCs) from phishing emails — without ever
opening links or attachments.

## Features
- Parse `.eml` files (headers + body)
- Extract URLs, domains, IPv4 addresses, email addresses
- Detect MD5 / SHA1 / SHA256 hash strings
- Detect attachment filenames from raw MIME
- Flag Reply-To mismatches and SPF/DKIM/DMARC failures
- Produce a formatted IOC report

## Requirements
- Python 3.10+
- No third-party libraries

## Usage
Place a sample at `Sample_Data/sample_phishing_email.eml` and run:

    python Scripts/ioc_analyser.py

Or open the script in VS Code and click ▶ Run.

## Safety
- Only analyze synthetic or public samples
- Never open links or attachments from untrusted emails
- Never upload confidential data to third-party services

## MITRE ATT&CK Mapping
- T1566 — Phishing
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
