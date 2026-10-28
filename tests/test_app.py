import re
import tempfile
import unittest
from pathlib import Path

import app


class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        app.BASE = Path(self.temp.name)
        app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = app.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def token(self):
        page = self.client.get("/").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def test_own_notes_and_csrf(self):
        token = self.token()
        self.client.post("/register", data={"email": "owner@example.test", "password": "A-long-test-password-123", "csrf_token": token})
        self.assertEqual(self.client.post("/notes", data={"body": "hello"}).status_code, 400)
        token = self.token()
        self.assertEqual(self.client.post("/notes", data={"body": "<script>", "csrf_token": token}).status_code, 302)
        self.assertIn(b"&lt;script&gt;", self.client.get("/").data)
        self.assertIn("DENY", self.client.get("/").headers["X-Frame-Options"])


if __name__ == "__main__":
    unittest.main()

