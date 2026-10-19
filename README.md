# 🛡️ PrivacyScan

[![CI](https://github.com/KashishSiddiqui/privacyscan/actions/workflows/ci.yml/badge.svg)](https://github.com/KashishSiddiqui/privacyscan/actions)

A zero-dependency static analysis tool that scans source code for **GDPR / privacy risks** and links every finding to the relevant GDPR article with a concrete fix.

## Why?
Privacy mistakes in software are often small and easy to overlook, such as email addresses written to log files, passwords hashed using MD5, or tracking scripts loaded before user consent is obtained.

I built PrivacyScan to explore how these issues can be detected automatically during software development. The tool scans source code using pattern-based rules, maps findings to relevant GDPR articles, and suggests potential fixes. I also extended the rule set with custom detection for Indian PAN numbers.

Throughout the project, I worked with unit testing, technical documentation, and continuous integration. PrivacyScan is designed as a first-level privacy check; it may produce false positives and does not replace a comprehensive privacy review.

## What it detects (11 rules)
| ID | Risk | Severity | GDPR |
|----|------|----------|------|
| PS001 | Personal data in logs | high | Art. 5(1)(c), 32 |
| PS002 | Hardcoded secrets | high | Art. 32 |
| PS003 | Weak password hashing (MD5/SHA-1) | high | Art. 32 |
| PS004 | IBAN in source | high | Art. 5(1)(f), 32 |
| PS005 | Hardcoded real email | medium | Art. 5(1)(c) |
| PS006 | Phone number in source | medium | Art. 5(1)(c) |
| PS007 | Trackers without consent | medium | Art. 6, 7, ePrivacy |
| PS008 | Tokens/PII in browser storage | medium | Art. 32 |
| PS009 | Cookies without Secure/HttpOnly | low | Art. 32 |
| PS010 | Plain HTTP URLs | low | Art. 32 |
| PS011 | Indian PAN number in source | high | Art. 5(1)(c), 32 |

## Usage
```bash
pip install -e .
privacyscan examples/demo_app                      # terminal report
privacyscan . --format html -o report.html         # visual report with score
privacyscan . --format json                        # machine-readable
privacyscan . --fail-on high                       # exit code 2 in CI if high risks exist
```
Suppress a false positive with a comment: `# privacyscan: ignore`.

## Privacy score
`score = 100 - (10 x high + 4 x medium + 1 x low)`, minimum 0.

## Design
- Rules are data (`rules.py`): adding a rule means adding one entry, no scanner changes.
- Scanner is pure (`scan_text`) and separate from file I/O, so it is easy to unit-test.
- CI mode (`--fail-on`) lets teams block risky commits automatically.

## Limitations & future work
- Regex-based, line-by-line: can produce false positives/negatives; it is not legal advice.
- Future: AST/data-flow analysis to track PII from input to log/storage, SARIF output for GitHub code scanning, GitHub Action packaging.

## License
MIT
