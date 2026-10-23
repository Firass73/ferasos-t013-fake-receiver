"""Submit TWO fixed FAKE messages; verify a real remote Ed25519 test receipt.

The TEST client signing key is not part of this public repository. Never send
real chats, site cookies, access tokens or a production signing key.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from server import BATCH, RECORDS, CANONICAL_RECORD_DIGEST, ACK_STATUS, json_bytes


def call(url, method="GET", data=None):
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def verify_remote_receipt(obj, issuer_key, nonce):
    if type(obj) is not dict or set(obj) != {"body", "signature"}:
        return False
    body = obj["body"]
    expected = {"type": "T013_RENDER_REMOTE_FAKE_SIGNED_ACK_V1", "batch": BATCH,
                "nonce": nonce, "recordDigest": CANONICAL_RECORD_DIGEST,
                "records": RECORDS, "archiveStatus": ACK_STATUS,
                "productionApproved": False, "issuer": "T013_RENDER_FREE_EPHEMERAL_RECEIVER"}
    if body != expected:
        return False
    try:
        issuer_key.verify(base64.b64decode(obj["signature"], validate=True), json_bytes(body))
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="T013 signed FAKE ONLY remote test")
    parser.add_argument("--url", required=True)
    parser.add_argument("--client-key", required=True, type=Path)
    parser.add_argument("--nonce", help="32-character lowercase hexadecimal; keep same nonce for retries")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--local-test", action="store_true", help="allow localhost http only")
    args = parser.parse_args()
    parts = urlsplit(args.url)
    if parts.scheme != "https" and not (args.local_test and parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1"}):
        raise SystemExit("Refusing non-HTTPS remote endpoint")
    base_url = args.url.rstrip("/")
    local_signer = serialization.load_pem_private_key(args.client_key.read_bytes(), password=None)
    if not isinstance(local_signer, Ed25519PrivateKey):
        raise SystemExit("TEST signing key must be Ed25519")
    local_public = base64.b64encode(local_signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    pinned_client_public = Path(__file__).with_name("client_test_public_key.txt").read_text().strip()
    if local_public != pinned_client_public:
        raise SystemExit("Wrong local test signing key; never send unpinned credentials")
    nonce = args.nonce or secrets.token_hex(16)
    if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise SystemExit("Invalid nonce")
    checks = []
    def checked(name, condition):
        checks.append({"check": name, "pass": bool(condition)})
        if not condition:
            raise RuntimeError("FAILED: " + name)
    status, health = call(base_url + "/health")
    checked("remote_test_health", status == 200 and health.get("testOnly") is True and health.get("batch") == BATCH)
    checked("remote_ephemeral_not_legacy_archive", health.get("storage") == "RENDER_FREE_EPHEMERAL_DISK_NOT_DURABLE")
    remote_public = base64.b64decode(health["receiverPublicKeyRawB64"], validate=True)
    remote_key = Ed25519PublicKey.from_public_bytes(remote_public)
    body = {"type": "T013_CLIENT_FAKE_REQUEST_V1", "batch": BATCH, "nonce": nonce,
            "records": RECORDS, "testOnly": True, "productionApproved": False}
    fake_signed = {"body": body, "clientSignature": base64.b64encode(local_signer.sign(json_bytes(body))).decode()}
    altered = {"body": {**body, "records": [{**RECORDS[0], "sha256": "0"*64}, RECORDS[1]]},
               "clientSignature": fake_signed["clientSignature"]}
    bad_status, bad_reply = call(base_url + "/fake-ack", "POST", json_bytes(altered))
    checked("forged_request_rejected", bad_status == 403 and "signature" not in bad_reply)
    first_status, first_reply = call(base_url + "/fake-ack", "POST", json_bytes(fake_signed))
    checked("remote_first_reply_lost_after_journal", first_status == 503 and "signature" not in first_reply)
    second_status, signed_ack = call(base_url + "/fake-ack", "POST", json_bytes(fake_signed))
    checked("remote_actual_signed_ack_verified", second_status == 200 and verify_remote_receipt(signed_ack, remote_key, nonce))
    third_status, replay = call(base_url + "/fake-ack", "POST", json_bytes(fake_signed))
    checked("signed_receipt_replayed_identically", third_status == 200 and replay == signed_ack)
    status, persisted = call(base_url + "/test-readback")
    expected = {"batch": BATCH, "nonce": nonce, "recordDigest": CANONICAL_RECORD_DIGEST,
                "recordCount": 2, "commits": 1, "archiveStatus": ACK_STATUS,
                "productionApproved": False}
    checked("remote_fake_journal_readback_exact_one_commit", status == 200 and persisted.get("committed") is True and persisted.get("journal") == expected)
    status, health2 = call(base_url + "/health")
    checked("remote_pinned_signer_identity_preserved", status == 200 and health2.get("receiverPublicKeyRawB64") == health.get("receiverPublicKeyRawB64"))
    checked("no_real_chat_archive_claim", signed_ack["body"]["archiveStatus"] == ACK_STATUS and signed_ack["body"]["productionApproved"] is False)
    output = {"result": "T013_REMOTE_RENDER_ED25519_TEST_ONLY_SIGNED_ACK_VERIFIED", "passed": len(checks),
              "total": len(checks), "checks": checks, "service": base_url,
              "receiverPublicKeySha256": hashlib.sha256(remote_public).hexdigest(),
              "nonce": nonce, "remoteSignedReceipt": signed_ack, "commits": 1,
              "ephemeralStorage": True, "actualDurableProductionArchive": False,
              "independentlyAdministeredKeyCustody": False, "realChatCaptureApproved": False}
    if args.output:
        args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf8")
    print(json.dumps({k: output[k] for k in ("result", "passed", "total", "ephemeralStorage", "actualDurableProductionArchive", "nonce")}, indent=2))


if __name__ == "__main__":
    main()
