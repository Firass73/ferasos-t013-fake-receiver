"""T-013 FAKE-ONLY remote Ed25519 receipt lab. Never use with real chat data.

The Render Free filesystem is ephemeral. This is NOT a durable production archive.
Client requests must carry an Ed25519 signature; no API tokens or code in env vars.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

BATCH = "T013-RENDER-FAKE-ONLY-20261023-001"
RECORDS = [
    {"id": "FAKE-CONV-001|FAKE-U-1|1", "sha256": "1232a6b129a84cdbbb624657e3d6fd179493472de5a70e276ceb3a3859477153"},
    {"id": "FAKE-CONV-001|FAKE-U-2|1", "sha256": "f0c38875e509f7b300343d3e94c7e554864e9e88650d974fdb144fb2ece060d3"},
]
CLIENT_PUBLIC_KEY_B64 = Path(__file__).with_name("client_test_public_key.txt").read_text(encoding="ascii").strip()
CANONICAL_RECORD_DIGEST = hashlib.sha256(json.dumps(RECORDS, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
ACK_STATUS = "TEST_EPHEMERAL_JOURNALED_NOT_PRODUCTION_ARCHIVED"
STATE_DIR = Path(os.environ.get("T013_TEST_STATE_DIR", "/tmp/ferasos_t013_ephemeral_receiver_20261023"))


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _no_dupes(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def strict_loads(raw):
    return json.loads(raw, object_pairs_hook=_no_dupes, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))


def fsync_dir(folder):
    if os.name == "posix":
        fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def exclusive_durable(path: Path, content: bytes):
    """Write exclusively; do not overwrite an acknowledged journal or signer."""
    candidate = path.with_name(path.name + ".new." + os.urandom(8).hex())
    with candidate.open("xb") as stream:
        os.chmod(candidate, 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        if path.exists():
            raise FileExistsError(path)
        os.replace(candidate, path)
        fsync_dir(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


class TestReceiver:
    """Single-worker lab only. No HA, external transaction store or live data."""
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(root, 0o700)
        self.key_path = root / "test-receiver-private-ed25519.bin"
        self.journal_path = root / "one-fake-journal.json"
        self.first_loss_path = root / "first-reply-lost.json"
        if self.key_path.exists():
            if os.name == "posix" and (self.key_path.stat().st_mode & 0o077):
                raise RuntimeError("Receiver signing key permissions too broad")
            private_bytes = self.key_path.read_bytes()
            if len(private_bytes) != 32:
                raise RuntimeError("Invalid receiver private key")
            self.signer = Ed25519PrivateKey.from_private_bytes(private_bytes)
        else:
            if self.journal_path.exists() or self.first_loss_path.exists():
                raise RuntimeError("Refuse key rotation after state exists")
            self.signer = Ed25519PrivateKey.generate()
            data = self.signer.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            exclusive_durable(self.key_path, data)
        self.public_raw = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.client_public = Ed25519PublicKey.from_public_bytes(base64.b64decode(CLIENT_PUBLIC_KEY_B64, validate=True))

    def expected_journal(self, nonce):
        return {"batch": BATCH, "nonce": nonce, "recordDigest": CANONICAL_RECORD_DIGEST,
                "recordCount": 2, "commits": 1, "archiveStatus": ACK_STATUS,
                "productionApproved": False}

    def readback(self):
        if not self.journal_path.exists():
            return {"committed": False, "scope": "FAKE_ONLY_EPHEMERAL_NOT_PRODUCTION"}
        try:
            value = strict_loads(self.journal_path.read_bytes())
            nonce = value.get("nonce") if type(value) is dict else None
            expected = self.expected_journal(nonce)
            if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
                raise ValueError("Invalid nonce")
            if set(value) != set(expected) or any(type(value[k]) is not type(v) or value[k] != v for k, v in expected.items()):
                raise ValueError("Journal content mismatch")
            return {"committed": True, "journal": value, "scope": "FAKE_ONLY_EPHEMERAL_NOT_PRODUCTION"}
        except (OSError, ValueError, TypeError):
            return {"committed": False, "invalidJournal": True, "scope": "FAKE_ONLY_EPHEMERAL_NOT_PRODUCTION"}

    def receive(self, raw):
        if len(raw) > 4096 or len(raw) == 0:
            return 400, {"error": "invalid_length"}
        try:
            package = strict_loads(raw)
            if type(package) is not dict or set(package) != {"body", "clientSignature"}:
                raise ValueError("invalid envelope")
            req = package["body"]
            if type(req) is not dict or list(req) != ["type", "batch", "nonce", "records", "testOnly", "productionApproved"]:
                raise ValueError("bad body")
            if req["type"] != "T013_CLIENT_FAKE_REQUEST_V1" or req["batch"] != BATCH:
                raise ValueError("invalid scope")
            nonce = req["nonce"]
            if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
                raise ValueError("invalid nonce")
            if req["records"] != RECORDS or req["testOnly"] is not True or req["productionApproved"] is not False:
                raise ValueError("not whitelisted synthetic data")
            sig = package["clientSignature"]
            if type(sig) is not str:
                raise ValueError("signature missing")
            self.client_public.verify(base64.b64decode(sig, validate=True), json_bytes(req))
        except Exception:
            return 403, {"error": "invalid_or_unsigned_fake_request"}
        prior = self.readback()
        expected = self.expected_journal(nonce)
        if prior.get("invalidJournal"):
            return 409, {"error": "corrupt_prior_journal"}
        if prior["committed"]:
            if prior["journal"] != expected:
                return 409, {"error": "conflicting_batch_or_nonce"}
        else:
            if self.first_loss_path.exists():
                return 409, {"error": "prior_commit_missing"}
            exclusive_durable(self.journal_path, json_bytes(expected))
        # Deliberate 503 AFTER journal fsync, to exercise retry without false ACK.
        if not self.first_loss_path.exists():
            exclusive_durable(self.first_loss_path, json_bytes({"firstReplyLostAfterCommit": True}))
            return 503, {"error": "test_only_simulated_reply_loss_after_commit"}
        body = {"type": "T013_RENDER_REMOTE_FAKE_SIGNED_ACK_V1", "batch": BATCH, "nonce": nonce,
                "recordDigest": CANONICAL_RECORD_DIGEST, "records": RECORDS,
                "archiveStatus": ACK_STATUS, "productionApproved": False,
                "issuer": "T013_RENDER_FREE_EPHEMERAL_RECEIVER"}
        signature = self.signer.sign(json_bytes(body))
        return 200, {"body": body, "signature": base64.b64encode(signature).decode("ascii")}


def make_handler(receiver):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return  # No raw request bodies or secrets in access logs.

        def reply(self, status, value):
            payload = json_bytes(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/health":
                self.reply(200, {"ready": True, "testOnly": True, "batch": BATCH,
                                 "receiverPublicKeyRawB64": base64.b64encode(receiver.public_raw).decode(),
                                 "storage": "RENDER_FREE_EPHEMERAL_DISK_NOT_DURABLE"})
            elif self.path == "/test-readback":
                self.reply(200, receiver.readback())
            else:
                self.reply(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != "/fake-ack":
                return self.reply(404, {"error": "not_found"})
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 < length <= 4096:
                    return self.reply(413, {"error": "invalid_length"})
                status, value = receiver.receive(self.rfile.read(length))
                self.reply(status, value)
            except Exception:
                self.reply(500, {"error": "internal_test_error_no_receipt"})
    return Handler


def main():
    port = int(os.environ.get("PORT", "10000"))
    if not 0 < port < 65536:
        raise RuntimeError("Invalid PORT")
    receiver = TestReceiver(STATE_DIR)
    server = HTTPServer(("0.0.0.0", port), make_handler(receiver))
    print("T013 FAKE-only ephemeral signed receipt lab started; never use real messages", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
