# L8 Protocol — v0.2

**Trustless webhook delivery via Ed25519 public key handshake, with optional payload encryption and request schemas.**

No shared secrets. No central authority. Ownership proven once via a signed challenge.
All future deliveries carry headers the receiver verifies locally — no database lookup, no round-trip.

---

## Why L8

Traditional webhook security stores a shared HMAC secret on both sides. That secret can be stolen, logged by accident, or forgotten to rotate. A compromised secret lets anyone forge deliveries silently.

L8 replaces the shared secret with public key cryptography. There is no secret to steal from a database. Verification is a single local `Ed25519.verify()` call against a cached public key — microseconds, zero network calls.

---

## How it works

1. Receiver publishes a public key at `GET /.well-known/l8`
2. Sender fetches that key and issues a signed challenge to prove both parties own their private keys
3. Trust is cached to disk as `l8-trust/{domain}.json` — the handshake runs once per domain
4. Every webhook delivery carries `X-L8-Signature` headers the receiver verifies locally
5. *(0.2, optional)* If the receiver publishes an X25519 key, the body is encrypted to it before signing
6. *(0.2, optional)* An upstream can publish JSON Schemas for its request bodies so senders reject bad requests before sending

Signing and encryption do different jobs. A signature proves who sent a message and that nobody changed it; anyone can still read it. Encryption hides the contents so only the receiver can read them. L8 0.1 signs. L8 0.2 can do both.

---

## Receiver endpoints (implement these to support L8)

### GET /.well-known/l8

```json
{
  "protocol_version":     "0.2",
  "service_name":         "your-service",
  "public_key":           "<base64 Ed25519 public key>",
  "challenge_endpoint":   "/l8/challenge",
  "supported_algorithms": ["ed25519"],
  "capabilities":         ["signed_payloads"]
}
```

### POST /l8/challenge

Sender request:
```json
{
  "challenge_id":      "<uuid>",
  "nonce":             "<uuid>",
  "timestamp":         1740000000,
  "sender_public_key": "<base64 Ed25519 public key>",
  "signature":         "<base64 Ed25519 sig of 'challenge_id:nonce'>"
}
```

Your response:
```json
{
  "challenge_id":        "<same uuid>",
  "nonce":               "<same nonce>",
  "receiver_signature":  "<base64 Ed25519 sig of 'challenge_id:nonce'>",
  "receiver_public_key": "<base64 Ed25519 public key>"
}
```

**Reject if:** timestamp is older than 5 minutes, or nonce has been seen before (replay protection).

---

## Signed delivery headers

After trust is established, all webhook POST requests include:

```
X-L8-Delivery-Id: <uuid>
X-L8-Timestamp:   <unix seconds>
X-L8-Key-Id:      <base64 first 8 bytes of sender public key>
X-L8-Signature:   <base64 Ed25519 sig of '{delivery_id}.{timestamp}.{base64(sha256(body))}'>
```

---

## Verification

```python
import base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def verify_l8(headers, body: bytes, sender_public_key_b64: str):
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(sender_public_key_b64))
    delivery_id = headers["X-L8-Delivery-Id"]
    timestamp   = headers["X-L8-Timestamp"]
    body_hash   = base64.b64encode(hashlib.sha256(body).digest()).decode()
    msg = f"{delivery_id}.{timestamp}.{body_hash}".encode()
    sig = base64.b64decode(headers["X-L8-Signature"])
    pub.verify(sig, msg)  # raises InvalidSignature if tampered
```

**On verification failure:** re-fetch the sender's `/.well-known/l8` to get a fresh public key (handles key rotation), then retry once before rejecting.

---

## Payload encryption (0.2, optional)

A receiver opts in by adding an X25519 key to `/.well-known/l8`. It is a separate key from the Ed25519 signing key.

```json
{
  "supported_algorithms":  ["ed25519", "x25519-hkdf-sha256-aes256gcm"],
  "capabilities":          ["signed_payloads", "encrypted_payloads"],
  "encryption_public_key": "<base64 X25519 public key, 32 bytes raw>"
}
```

A sender that sees `encrypted_payloads` MUST encrypt every delivery to that receiver:

1. Generate a fresh ephemeral X25519 key pair for the delivery.
2. `shared = X25519(ephemeral_private, encryption_public_key)`
3. `key = HKDF-SHA256(ikm = shared, salt = ephemeral_public || encryption_public_key, info = "l8/0.2 payload", length = 32)`
4. `ciphertext = AES-256-GCM(key, nonce = 12 random bytes, plaintext = body, aad = "{delivery_id}.{timestamp}")`
5. Sign the **ciphertext** exactly as in [Signed delivery headers](#signed-delivery-headers) (encrypt-then-sign).

Extra headers on an encrypted delivery:

```
X-L8-Encryption:    x25519-hkdf-sha256-aes256gcm
X-L8-Ephemeral-Key: <base64 ephemeral X25519 public key>
X-L8-Nonce:         <base64 12-byte nonce>
X-L8-Content-Type:  <content type of the plaintext, e.g. application/json>
Content-Type:       application/l8-encrypted
```

The body is the raw ciphertext (GCM tag appended). The receiver verifies the signature first, then decrypts. The AAD binds the ciphertext to its delivery id and timestamp, so it can't be replayed under a different delivery. The salt binds it to the receiver's key.

```python
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def decrypt_l8(headers, ciphertext: bytes, enc_private_key, enc_public_raw: bytes) -> bytes:
    eph = base64.b64decode(headers["X-L8-Ephemeral-Key"])
    shared = enc_private_key.exchange(X25519PublicKey.from_public_bytes(eph))
    key = HKDF(algorithm=SHA256(), length=32, salt=eph + enc_public_raw,
               info=b"l8/0.2 payload").derive(shared)
    aad = f"{headers['X-L8-Delivery-Id']}.{headers['X-L8-Timestamp']}".encode()
    return AESGCM(key).decrypt(base64.b64decode(headers["X-L8-Nonce"]), ciphertext, aad)
```

HTTPS already encrypts the connection. L8 encryption protects the body end to end, through anything that terminates TLS in the middle: a relay, a gateway someone else runs, a logging proxy.

---

## Request schemas (0.2, optional)

An upstream API can publish the JSON Schema (draft 2020-12) each route accepts, so a sender rejects a malformed request before spending an upstream call on it.

```json
{
  "capabilities":    ["signed_payloads", "request_schemas"],
  "schema_hash":     "sha256:<hex>",
  "request_schemas": {
    "POST /v1/chat/completions": {
      "type": "object",
      "required": ["model", "messages"]
    }
  }
}
```

- Keys are `"METHOD /path"`. Method is case-insensitive; path matches exactly, without the query string.
- `schema_hash` is REQUIRED when `request_schemas` is present. It SHOULD be `sha256:` plus the hex SHA-256 of the RFC 8785 canonical JSON of `request_schemas`, but senders treat it as an opaque version string and only compare it for equality.
- The upstream SHOULD send `X-Aqueduct-Schema-Hash: <schema_hash>` on every response. A sender that sees a different value drops its cached schemas and its trust for that domain, refetches `/.well-known/l8`, and re-runs the handshake.
- Senders cache schemas for at most 10 minutes, MUST NOT fetch external `$ref`s (a schema from a remote party must not become an SSRF primitive), and SHOULD reject a mismatch with HTTP `422`.
- Routes without a schema, and metadata that fails to fetch or compile, are not checked.

---

## Trust cache

One file per trusted domain: `l8-trust/{domain}.json`

```json
{
  "domain":           "https://example.com",
  "public_key":       "<base64>",
  "validated_at":     1740000000,
  "protocol_version": "0.2",
  "capabilities":     ["signed_payloads", "encrypted_payloads"],
  "encryption_public_key": "<base64 X25519, only if advertised>"
}
```

To revoke: delete the file. The handshake re-runs on next delivery.

---

## Key management

| Method | How |
|--------|-----|
| Environment variable | `L8_PRIVATE_KEY=<base64 raw Ed25519 private key>` |
| Key file | `.l8-key` — raw bytes, auto-generated on first start |

Only the private key is needed. The public key is derived from it.

---

## Graceful degradation

L8 is opt-in. If `/.well-known/l8` returns non-200, delivery proceeds without signed headers. Receivers that don't implement L8 are completely unaffected.

---

## Roadmap

| Version | Feature |
|---------|---------|
| 0.1 | Signed delivery, challenge handshake, trust cache |
| **0.2** | Payload encryption (X25519 + AES-256-GCM), per-route request schemas ← *current* |
| 0.3 | Formalized key rotation and trust expiry |
| 1.0 | Stable — no breaking changes |

---

## Reference implementations

- **[Aquifer](https://github.com/rjpruitt16/aquifer)** — Go, sender side: signing, encryption, schema validation
- **[l8_receiver.py](https://github.com/rjpruitt16/aquifer/blob/main/tests/l8_receiver.py)** — Python, receiver side, reference implementation with tests

Machine-readable spec: [`spec.json`](spec.json)
