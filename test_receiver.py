"""Local tests exercise the SAME stdlib HTTP handler intended for Render."""
import base64
import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from http.server import HTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import server

class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t013-fake-remote-test-")
        self.addCleanup(self.temp.cleanup)
        self.client = Ed25519PrivateKey.generate()
        self.previous_key = server.CLIENT_PUBLIC_KEY_B64
        server.CLIENT_PUBLIC_KEY_B64 = base64.b64encode(self.client.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.addCleanup(setattr, server, "CLIENT_PUBLIC_KEY_B64", self.previous_key)
        self.state = server.TestReceiver(Path(self.temp.name))
        self.nonce = "a" * 32
        self.body = {"type": "T013_CLIENT_FAKE_REQUEST_V1", "batch": server.BATCH, "nonce": self.nonce,
                     "records": server.RECORDS, "testOnly": True, "productionApproved": False}

    def submit(self, raw):
        return self.state.receive(raw)

    def envelope(self, body=None):
        body = body or self.body
        return server.json_bytes({"body": body, "clientSignature": base64.b64encode(self.client.sign(server.json_bytes(body))).decode()})

    def test_real_signer_journal_once_lost_response_then_replay(self):
        self.assertEqual(self.submit(self.envelope())[0], 503)
        self.assertEqual(self.state.readback()["journal"]["commits"], 1)
        code, ack = self.submit(self.envelope())
        self.assertEqual(code, 200)
        self.state.signer.public_key().verify(base64.b64decode(ack["signature"]), server.json_bytes(ack["body"]))
        self.assertEqual(self.submit(self.envelope()), (code, ack))
        self.assertEqual(self.state.readback()["journal"]["commits"], 1)

    def test_receiver_restart_pins_signer(self):
        self.submit(self.envelope())
        key1 = self.state.public_raw
        self.state = server.TestReceiver(Path(self.temp.name))
        self.assertEqual(self.state.public_raw, key1)
        self.assertEqual(self.submit(self.envelope())[0], 200)

    def test_corrupt_journal_not_signed(self):
        self.submit(self.envelope())
        journal = self.state.journal_path
        data = json.loads(journal.read_text())
        data["commits"] = True
        journal.write_text(json.dumps(data))
        result = self.submit(self.envelope())
        self.assertEqual(result[0], 409)
        self.assertNotIn("signature", result[1])

    def test_wrong_nonce_conflicts_after_journaled(self):
        self.submit(self.envelope())
        changed = {**self.body, "nonce": "f"*32}
        self.assertEqual(self.submit(self.envelope(changed))[0], 409)

    def test_unsigned_modified_dummy_and_duplicates_rejected(self):
        wrong = {**self.body, "records": [{**server.RECORDS[0], "sha256": "0"*64}, server.RECORDS[1]]}
        malicious = server.json_bytes({"body": wrong, "clientSignature": base64.b64encode(self.client.sign(server.json_bytes(self.body))).decode()})
        self.assertEqual(self.submit(malicious)[0], 403)
        self.assertFalse(self.state.journal_path.exists())
        duplicated = self.envelope().replace(b'"batch":', b'"batch":"WRONG","batch":', 1)
        self.assertEqual(self.submit(duplicated)[0], 403)
        self.assertFalse(self.state.journal_path.exists())
        nan = self.envelope().replace(b'"testOnly":true', b'"testOnly":NaN', 1)
        self.assertEqual(self.submit(nan)[0], 403)

    def test_missing_key_never_rotated_after_journal(self):
        self.submit(self.envelope())
        self.state.key_path.unlink()
        with self.assertRaisesRegex(RuntimeError, "Refuse key rotation"):
            server.TestReceiver(Path(self.temp.name))

    def test_http_handler_real_local_transport(self):
        httpd = HTTPServer(("127.0.0.1", 0), server.make_handler(self.state))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            with urllib.request.urlopen(base + "/health", timeout=2) as response:
                self.assertTrue(json.loads(response.read())["testOnly"])
            def post():
                req = urllib.request.Request(base + "/fake-ack", data=self.envelope(), headers={"Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(req, timeout=2) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read())
            self.assertEqual(post()[0], 503)
            status, value = post()
            self.assertEqual(status, 200)
            self.state.signer.public_key().verify(base64.b64decode(value["signature"]), server.json_bytes(value["body"]))
            with urllib.request.urlopen(base + "/test-readback", timeout=2) as response:
                self.assertEqual(json.loads(response.read())["journal"]["commits"], 1)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(2)

if __name__ == "__main__":
    unittest.main(verbosity=2)
