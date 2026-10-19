import hashlib
import logging

import requests

logger = logging.getLogger(__name__)
DB_PASSWORD = "SuperSecret123"
CONTACT = "max.mustermann@gmail.com"
SUPPORT_PHONE = "+49 170 1234567"
IBAN = "DE89 3704 0044 0532 0130 00"


def register(email, password, phone, resp):
    logger.info("New user %s with phone %s", email, phone)
    hashed = hashlib.md5(password.encode()).hexdigest()
    resp.set_cookie("session", hashed)
    requests.get("http://api.partner-site.com/sync")
    safe = "user@example.com"  # fine
    return safe
