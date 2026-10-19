"""Privacy rules. Each rule maps a code pattern to a GDPR article and a fix."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str  # high | medium | low
    article: str
    message: str
    fix: str
    pattern: re.Pattern
    unless: re.Pattern = None


def _r(p):
    return re.compile(p, re.I)


RULES = [
    Rule("PS001", "Personal data in logs", "high", "Art. 5(1)(c), Art. 32",
         "Personal data (email, phone, IP, password...) is written to logs.",
         "Log opaque IDs instead, or mask the value before logging.",
         _r(r"(print|logging\.\w+|logger\.\w+|log\.\w+|console\.(log|info|debug))\s*\(.*"
            r"\b(email|e-mail|phone|password|passwd|ssn|iban|ip_?addr(ess)?|client_ip|remote_addr|birth\w*)\b")),
    Rule("PS002", "Hardcoded secret", "high", "Art. 32",
         "A password, key or token is hardcoded in source code.",
         "Load secrets from environment variables or a secrets manager.",
         _r(r"(password|passwd|secret|api_?key|token)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]")),
    Rule("PS003", "Weak password hashing", "high", "Art. 32",
         "MD5/SHA-1 is used for passwords and is not safe.",
         "Use bcrypt, scrypt or Argon2 with a per-user salt.",
         _r(r"\b(md5|sha1)\b.*(password|passwd|pwd)|(password|passwd|pwd).*\b(md5|sha1)\b")),
    Rule("PS004", "IBAN in source", "high", "Art. 5(1)(f), Art. 32",
         "A bank account number (IBAN) appears in the code.",
         "Remove it; never keep real financial data in code or test fixtures.",
         _r(r"\bDE\d{2}(?:\s?\d{4}){4}\s?\d{2}\b")),
    Rule("PS005", "Hardcoded email address", "medium", "Art. 5(1)(c)",
         "A real-looking email address is stored in code.",
         "Use configuration or placeholder addresses (user@example.com).",
         _r(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
         _r(r"@(example\.(com|org|net)|localhost)|no-?reply")),
    Rule("PS006", "German phone number in source", "medium", "Art. 5(1)(c)",
         "A phone number appears in the code.",
         "Remove personal numbers from source and test data.",
         _r(r"(\+49|0049)[\s\d/-]{8,}")),
    Rule("PS007", "Tracker without consent", "medium", "Art. 6, Art. 7, ePrivacy",
         "Third-party tracking script found; consent is required before loading it.",
         "Load trackers only after explicit opt-in via a consent banner.",
         _r(r"google-analytics\.com|googletagmanager\.com|gtag\(|fbq\(|connect\.facebook\.net|hotjar|mixpanel")),
    Rule("PS008", "Personal data in browser storage", "medium", "Art. 32",
         "Tokens or personal data are stored in localStorage/sessionStorage.",
         "Prefer HttpOnly cookies and store as little as possible.",
         _r(r"(localStorage|sessionStorage)\.setItem\(\s*['\"][^'\"]*(token|email|password|user|phone)")),
    Rule("PS009", "Cookie without security flags", "low", "Art. 32",
         "Cookie is set without Secure/HttpOnly flags.",
         "Set Secure, HttpOnly and SameSite on cookies.",
         _r(r"set_cookie\(|document\.cookie\s*="), _r(r"secure|httponly")),
    Rule("PS010", "Unencrypted HTTP", "low", "Art. 32",
         "Data may be sent over plain HTTP.",
         "Use HTTPS for all external requests.",
         _r(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org)")),
    Rule("PS011", "Indian PAN number in source", "high", "Art. 5(1)(c), Art. 32",
         "A PAN (Indian tax ID) appears in the code.",
         "Remove real ID numbers from code and test data.",
         _r(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
]
