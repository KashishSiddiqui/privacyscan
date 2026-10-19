import unittest

from privacyscan.scanner import scan_text, score


def ids(code):
    return {f.rule_id for f in scan_text(code)}


class TestRules(unittest.TestCase):
    def test_log_pii(self):
        self.assertIn("PS001", ids('logger.info("user %s", email)'))

    def test_log_safe(self):
        self.assertNotIn("PS001", ids('logger.info("user %s", user_id)'))

    def test_secret(self):
        self.assertIn("PS002", ids('API_KEY = "abcdef123456"'))

    def test_weak_hash(self):
        self.assertIn("PS003", ids("h = hashlib.md5(password.encode())"))

    def test_iban(self):
        self.assertIn("PS004", ids('x = "DE89 3704 0044 0532 0130 00"'))

    def test_email_real_vs_example(self):
        self.assertIn("PS005", ids('a = "max@gmail.com"'))
        self.assertNotIn("PS005", ids('a = "user@example.com"'))

    def test_tracker(self):
        self.assertIn("PS007", ids("fbq('track','PageView')"))

    def test_cookie_flags(self):
        self.assertIn("PS009", ids('resp.set_cookie("a", b)'))
        self.assertNotIn("PS009", ids('resp.set_cookie("a", b, secure=True, httponly=True)'))

    def test_ignore_comment(self):
        self.assertEqual(ids('API_KEY = "abcdef123456"  # privacyscan: ignore'), set())

    def test_score(self):
        self.assertEqual(score([]), 100)
        self.assertEqual(score(scan_text('API_KEY = "abcdef123456"')), 90)

    def test_pan(self):
        self.assertIn("PS011", ids('pan = "ABCDE1234F"'))


if __name__ == "__main__":
    unittest.main()
