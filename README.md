# Feras OS — T-013 Remote Receiver (FAKE-only proof)

This is a **synthetic test**, not a production ChatGPT archiver. It accepts exactly two hardcoded FAKE record identifiers/hashes; nothing else. The code is readable Python, not stored in a Render environment variable. There are **no secrets in this repository**. An Ed25519 client public key is pinned in `client_test_public_key.txt`; the matching private **test** key remains only on the authorized local computer.

## Files

- `server.py`: Python standard-library HTTP server plus `cryptography` Ed25519 signatures. It signs a receipt only after its dummy journal is written, synced, and validated.
- `client_verify.py`: local, independently verifies the server's Ed25519 signature, the whitelisted fake records, nonce, retry, and remote journal readback.
- `test_receiver.py`: local automated security and HTTP tests.
- `client_test_public_key.txt`: non-secret pinned Ed25519 public key.
- `requirements.txt`: external dependency list, only `cryptography`.

## Render Free deployment (only after creating an accessible GitHub repository)

Use `Render > New Web Service` or the connected Render app with these **transparent** settings:

| Setting | Value |
|---|---|
| Runtime | Python |
| Source | This repository, branch `main` |
| Build command | `pip install -r requirements.txt` |
| Start command | `python server.py` |
| Plan | **Free** |
| Auto-deploy | **Off** |
| Secrets / environment variables | **None required** |

The service binds to Render's assigned `PORT`. Public `GET /health` exposes only test scope and receiver **public** key; `GET /test-readback` shows dummy state. `POST /fake-ack` requires a valid Ed25519 signature by the locally pinned **test client** key and will never accept real chat data. It intentionally returns HTTP 503 for the first valid attempt after fsync-journaling, then a signed receipt on exact replay. `productionApproved` is always `false`, and archival status is always `TEST_EPHEMERAL_JOURNALED_NOT_PRODUCTION_ARCHIVED`.

### Local tests

```sh
pip install -r requirements.txt
python -m unittest -v test_receiver
```

### Remote verification

On the authorized computer, using the disposable **local test-only private key** stored outside the repository:

```sh
python client_verify.py --url https://YOUR-NEW-SERVICE.onrender.com --client-key PATH_TO_LOCAL_TEST_ONLY_PRIVATE_KEY --output cloud_proof.json
```

The client performs a forged-request rejection, verifies the simulated lost first response (503), confirms that a real Ed25519 signed receipt arrives upon replay and is byte-identical on a second replay, and independently reads back the server's **dummy** journal (exactly one commit).

## Limitations and cleanup

**A Render Free web service filesystem is ephemeral.** `fsync` helps with OS-level file writes but does not create off-instance storage: on restart/replacement the test journal and receiver private key can disappear. The test **does not prove recoverability across host loss, independent administrative custody, or a durable production archival ACK**. Do **not** store real ChatGPT history, secrets, cookies, browser data, or personal messages. Do not claim that the remote service is an independent third-party administrator: the Render workspace remains under the same user's control.

After documenting the signed synthetic receipt, delete the new **T-013 test web service** and the disposable local private test key; leave unrelated Render services and existing Oracle/Chatwoot/n8n untouched. Previously revoked source consent remains revoked; LIVE_CHATGPT_CAPTURE is **NO_GO**.
