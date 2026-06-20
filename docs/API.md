# PoA-Attest Oracle — API Reference

> **Status:** This document reflects `oracle.py` v0.1.0 (single-node signed oracle). The endpoint shapes, scope contract, and signature scheme are stable within the 0.1.x line.

This is the canonical reference for the HTTP surface exposed by the `poa-oracle` sidecar. For installation, configuration, and a quick start, see [README.md](../README.md).

---

## Scope contract (non-negotiable)

Every successful response carries a `scope` string. The signed `attestation` block attests **only**:

- the queried identity is **physically present hardware** (fingerprint + anti-emulation passed), and
- the **self-reported architecture class** (e.g. `vintage-ppc`, `modern-x86`).

It does **NOT** attest work quality, output authenticity, operator intent, or that any specific computation occurred. A real PowerPC G4 running a scam still passes.

> Honest labeling: this is a **single-node signed oracle**. Multi-node N-of-5 co-signing is future work and is NOT claimed here.

---

## Base URL

```
http://<host>:<port>
```

Defaults: `host=127.0.0.1`, `port=8097`. Override with `python -m oracle --host 0.0.0.0 --port 9000`.

---

## Endpoints

### `GET /health`

Liveness probe. Returns the oracle's Ed25519 public key so clients can pin it.

**Response 200**

```json
{
  "status": "ok",
  "oracle": "poa-attest",
  "pubkey": "a1b2c3d4e5f6...64-hex-chars"
}
```

**Errors:** none.

**Example**

```bash
curl -s http://127.0.0.1:8097/health
```

---

### `GET /oracle/attest/<id>`

Look up the latest attestation for one identity. `<id>` may be any of:

| Form | Example |
|------|---------|
| Miner ID (string) | `g4-powerbook-115` |
| RTC wallet address | `RTC6686166a9f6afc55a8ff5ebff232be8c956c024e` |
| Signing public key (hex) | `5e8c...40-hex-chars` |

The lookup is matched against the `miner` and `signing_pubkey` columns of the RustChain node's `miner_attest_recent` table (read-only). The most recent row wins.

**Response 200 — identity found**

```json
{
  "oracle_version": "0.1.0-single-node",
  "scope": "attests: hardware is physically present and non-emulated, plus its self-reported architecture class. does NOT attest: work quality, output authenticity, operator intent, or that any specific computation occurred.",
  "attestation": {
    "query": "g4-powerbook-115",
    "found": true,
    "is_physical": true,
    "anti_emulation_pass": true,
    "device_family": "PowerPC G4",
    "device_arch": "g4",
    "antiquity_class": "vintage-ppc",
    "attestation_age_s": 8421,
    "fresh": true
  },
  "issued_at": 1749924891,
  "oracle_pubkey": "a1b2c3d4e5f6...64-hex-chars",
  "oracle_signature": "f0e1d2c3...128-hex-chars",
  "verify_hint": "Ed25519 verify oracle_signature over compact key-sorted JSON of {oracle_version,scope,attestation,issued_at}"
}
```

**Response 200 — identity not found**

```json
{
  "oracle_version": "0.1.0-single-node",
  "scope": "...",
  "attestation": {
    "query": "unknown-miner",
    "found": false,
    "is_physical": null,
    "anti_emulation_pass": null,
    "device_family": null,
    "antiquity_class": null,
    "attestation_age_s": null,
    "fresh": false
  },
  "issued_at": 1749924891,
  "oracle_pubkey": "...",
  "oracle_signature": "...",
  "verify_hint": "..."
}
```

> Even when `found: false`, the envelope is signed. This lets clients prove the oracle itself was queried, and at what time, even for negative answers.

**Response 400** — missing identity in the URL.

```json
{ "error": "missing identity" }
```

**Response 503** — RustChain database unavailable (read-only failure).

```json
{ "error": "data source unavailable: <sqlite error>" }
```

**Response 404** — unknown path. The body lists valid endpoints.

```json
{ "error": "not found", "endpoints": ["/oracle/attest/<id>", "/health"] }
```

---

## Field reference

### Envelope (signed)

| Field | Type | Description |
|-------|------|-------------|
| `oracle_version` | string | Semantic version of the oracle software. |
| `scope` | string | The non-negotiable scope contract, repeated on every response. |
| `attestation` | object | The verdict (see below). |
| `issued_at` | int (unix seconds) | When this response was assembled. |
| `oracle_pubkey` | string (hex) | Ed25519 public key of the oracle signer (64 hex chars). |
| `oracle_signature` | string (hex) | Ed25519 signature over the canonical envelope (see Verification). |
| `verify_hint` | string | Human-readable signature scheme description. |

### Attestation

| Field | Type | Description |
|-------|------|-------------|
| `query` | string | Echo of the path parameter. |
| `found` | bool | `true` if the identity was located in `miner_attest_recent`. |
| `is_physical` | bool \| null | `true` if fingerprint + anti-emulation checks passed. `null` if `found=false`. |
| `anti_emulation_pass` | bool \| null | Same as `is_physical` (kept separate for future divergence). |
| `device_family` | string \| null | Self-reported family (e.g. `Apple M1`, `PowerPC G4`). |
| `device_arch` | string \| null | Self-reported architecture token (e.g. `g4`, `m1`, `x86_64`). |
| `antiquity_class` | string \| null | Coarse antiquity bucket — see [Antiquity classes](#antiquity-classes). |
| `attestation_age_s` | int \| null | Seconds since the node's `ts_ok`. `null` if not found. |
| `fresh` | bool | `true` if `attestation_age_s < 86400` (24h, matches the node's validity window). |

> **Note:** No field is ever named a bare `verified`. The signed field is `attestation`, with `is_physical` and `fresh` as two orthogonal facts clients can compose.

---

## Antiquity classes

The oracle maps each `device_arch` to a coarse antiquity bucket for downstream consumers. These are **labels only** — not uniqueness claims or reward multipliers.

| `device_arch` (substring) | `antiquity_class` |
|---------------------------|---------------------|
| `g3`, `g4`, `g5`, `powerpc` | `vintage-ppc` |
| `power8` | `exotic-server` |
| `sparc`, `mips`, `riscv` | `exotic` |
| `retro`, `pentium4`, `core2` | `retro-x86` |
| `apple_silicon`, `aarch64`, `m1`, `m2`, `m3`, `m4` | `modern-arm` |
| `modern`, `x86_64`, `x86` | `modern-x86` |
| (anything else) | `unknown` |

The matching is substring-based, lowercase, and case-insensitive.

---

## Signature verification

The signature is computed over the **canonical envelope** — i.e. the JSON of `{oracle_version, scope, attestation, issued_at}` serialized with `sort_keys=True` and `separators=(",", ":")` (no whitespace). The `oracle_pubkey` and `oracle_signature` fields are **appended after signing** so they are not part of the signed bytes.

**Pseudocode (Python)**

```python
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

envelope = json.loads(response_bytes)

# Build the exact message that was signed
message_fields = {
    "oracle_version": envelope["oracle_version"],
    "scope":          envelope["scope"],
    "attestation":    envelope["attestation"],
    "issued_at":      envelope["issued_at"],
}
message = json.dumps(message_fields, sort_keys=True, separators=(",", ":")).encode()

# Verify
pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(envelope["oracle_pubkey"]))
pubkey.verify(bytes.fromhex(envelope["oracle_signature"]), message)
# raises cryptography.exceptions.InvalidSignature on failure
```

**Pseudocode (Node.js)**

```js
const ed = require('@noble/ed25519');
const canonical = (o) => JSON.stringify(
  { oracle_version: o.oracle_version, scope: o.scope, attestation: o.attestation, issued_at: o.issued_at },
  Object.keys({ oracle_version:1, scope:1, attestation:1, issued_at:1 }).sort()
).replace(/ /g, '');

const msg = Buffer.from(canonical(envelope));
const sig = Buffer.from(envelope.oracle_signature, 'hex');
const pub = Buffer.from(envelope.oracle_pubkey, 'hex');
const ok  = ed.verify(sig, msg, pub);
```

---

## Configuration

The sidecar takes four CLI flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--db` | `/root/rustchain/rustchain_v2.db` | Path to the RustChain node's SQLite database. Opened `mode=ro`. |
| `--key` | `~/.poa-oracle-key.json` | Oracle Ed25519 signing key. Created with `0600` perms on first run. |
| `--host` | `127.0.0.1` | Bind address. Use `0.0.0.0` to accept external connections (TLS recommended). |
| `--port` | `8097` | TCP port. |

> **Security note:** The signing key is the oracle's identity. Anyone with this key can mint valid signatures that say "yes, this hardware is real." Restrict filesystem access (`chmod 600`, owned by the oracle process user), and rotate by deleting the key file (a new Ed25519 keypair is generated on next start).

---

## Failure modes

| Symptom | Likely cause |
|---------|--------------|
| `503 data source unavailable: <sqlite error>` | The RustChain node's DB is missing, locked, or in a read-only directory. |
| `400 missing identity` | You called `/oracle/attest/` with a trailing slash and no ID. |
| Verification fails | The oracle's `pubkey` changed (key rotated) OR the response was tampered with. |
| `attestation.found: false` | Identity not in `miner_attest_recent` (never mined, or pruned by the node's 24h window). |

---

## Versioning

| Version | Released | Notes |
|---------|----------|-------|
| `0.1.0-single-node` | 2026-06 | First public release. Single-node signed oracle, HTTP/JSON. |
| `0.2.x` (planned) | TBD | Multi-node N-of-5 co-signing. NOT claimed in 0.1.x. |

Breaking changes to the envelope shape or the scope contract will bump the major version. Field additions within the `attestation` object are non-breaking.
