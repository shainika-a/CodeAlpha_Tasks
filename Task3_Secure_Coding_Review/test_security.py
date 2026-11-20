"""Regression tests for the fixes. Uses a temporary database, not live accounts."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
import remediated_app as target
from werkzeug.security import check_password_hash, generate_password_hash


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = target.DB
        target.DB = Path(self.temp.name) / "test.db"
        self.password = "LocalTestPassword123!"
        with sqlite3.connect(target.DB) as db:
            db.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
            db.execute("INSERT INTO users VALUES (?, ?)", ("student", generate_password_hash(self.password)))
        self.client = target.app.test_client()

    def tearDown(self):
        target.DB = self.old_db
        self.temp.cleanup()

    def test_valid_credentials_still_work(self):
        result = self.client.post("/login", data={"username": "student", "password": self.password})
        self.assertEqual(result.status_code, 200)

    def test_sql_injection_does_not_bypass_login(self):
        result = self.client.post("/login", data={"username": "' OR 1=1 -- ", "password": "wrong"})
        self.assertEqual(result.status_code, 401)

    def test_wrong_password_rejected(self):
        self.assertEqual(self.client.post("/login", data={"username": "student", "password": "wrong"}).status_code, 401)

    def test_html_is_escaped(self):
        result = self.client.get("/greet", query_string={"name": "<script>alert(1)</script>"})
        text = result.get_data(as_text=True)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)

    def test_password_not_stored_as_plaintext(self):
        with sqlite3.connect(target.DB) as db:
            stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotEqual(stored, self.password)
        self.assertTrue(check_password_hash(stored, self.password))

    def test_oversized_request_rejected(self):
        self.assertEqual(self.client.post("/login", data={"username": "x" * 20000, "password": "x"}).status_code, 413)

    def test_headers_and_length_limit(self):
        self.assertEqual(self.client.get("/greet", query_string={"name": "x" * 101}).status_code, 400)
        result = self.client.get("/greet")
        self.assertEqual(result.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", result.headers["Content-Security-Policy"])
        self.assertFalse(target.app.debug)


if __name__ == "__main__":
    unittest.main()
