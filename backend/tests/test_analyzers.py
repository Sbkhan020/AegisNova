import unittest
from app.analyzers import url_analysis, email_analysis, network_analysis, file_analysis

class AnalyzerTests(unittest.TestCase):
    def test_url_does_not_fetch_and_flags_http(self):
        result = url_analysis("http://example.com/login")
        self.assertIn("Connection does not use HTTPS", result["findings"])
    def test_email_flags_credential_pressure(self):
        result = email_analysis("Urgent: verify your account password immediately")
        self.assertGreater(result["score"], 0)
    def test_network_scope_is_passive(self):
        result = network_analysis("192.168.1.0/24")
        self.assertEqual(result["metadata"]["addresses"], 256)
        self.assertIn("No hosts or ports were contacted", result["findings"])
    def test_file_hash(self):
        result = file_analysis(b"hello", "note.txt")
        self.assertEqual(result["metadata"]["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

if __name__ == "__main__": unittest.main()
