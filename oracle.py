#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
PoA-Attest oracle — read-only hardware-authenticity attestation, re-exposed
under an explicit scope contract that external agents/DePIN systems can query.

Architecture: a SIDECAR. It reads the RustChain node's existing
`miner_attest_recent` data READ-ONLY and re-publishes the anti-emulation /
antiquity verdict, reward-decoupled and signed. It does NOT modify, write to,
or run inside the consensus node — zero blast radius on consensus.

    GET /oracle/attest/<id>      id = miner-id, RTC address, or signing pubkey
    GET /health

THE SCOPE CONTRACT (non-negotiable, per the ecosystem-attractors plan):
The verdict attests ONLY that hardware is physically present, non-emulated, and
its self-reported architecture class. It does NOT attest work quality, output
authenticity, operator intent, or that any specific computation happened. A real
G4 running a scam still passes. Every response carries the `scope` string, and
NO field is ever named a bare `verified` — the signed field is `attestation`.

Honest labeling: this is a SINGLE-node signed oracle. Multi-node N-of-5
co-signing is future work and is NOT claimed here.

Identity namespaces are also part of that honesty: `miner` is the node's
primary key, `signing_pubkey` is self-reported by the attesting miner. They are
resolved separately (see OracleDB.lookup) and every verdict says which one
answered, so a signed verdict can never be about somebody else's hardware.
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ATTESTATION_TTL = 86400  # 24h; matches the node's attestation validity window

# An Ed25519 public key as the node stores it: 32 bytes, lowercase hex.
# Identities that do not match this are looked up ONLY against the node's
# primary key (`miner`) — see OracleDB.lookup().
_ED25519_PUBKEY_HEX = re.compile(r"^[0-9a-f]{64}$")

SCOPE = (
    "attests: hardware is physically present and non-emulated, plus its "
    "self-reported architecture class. does NOT attest: work quality, output "
    "authenticity, operator intent, or that any specific computation occurred."
)

# device_arch -> coarse antiquity class (labels only; not a uniqueness claim)
_ANTIQUITY = {
    "g3": "vintage-ppc", "g4": "vintage-ppc", "g5": "vintage-ppc",
    "powerpc": "vintage-ppc", "power8": "exotic-server",
    "sparc": "exotic", "mips": "exotic", "riscv": "exotic",
    "retro": "retro-x86", "pentium4": "retro-x86", "core2": "retro-x86",
    "apple_silicon": "modern-arm", "aarch64": "modern-arm",
    "m1": "modern-arm", "m2": "modern-arm", "m3": "modern-arm", "m4": "modern-arm",
    "modern": "modern-x86", "x86_64": "modern-x86", "x86": "modern-x86",
}


def _antiquity_class(device_arch):
    a = (device_arch or "").lower()
    for k, v in _ANTIQUITY.items():
        if k in a:
            return v
    return "unknown"


class OracleDB:
    """Read-only accessor over the node's rustchain_v2.db."""

    def __init__(self, db_path):
        self.db_path = db_path

    COLUMNS = ("SELECT miner, ts_ok, device_family, device_arch, entropy_score, "
               "fingerprint_passed, signing_pubkey FROM miner_attest_recent ")

    def lookup(self, ident):
        """Resolve one identity to at most one attestation row. Read-only.

        The two identity namespaces are NOT equivalent and are not unioned:

        * `miner` is the node's PRIMARY KEY — assigned, unique, rate-limited.
        * `signing_pubkey` is whatever the caller put in the attestation body's
          `public_key` field. The node verifies it only when a `signature` is
          also supplied (the unsigned path is explicitly supported), so it is
          attacker-chosen data.

        Resolving them in one `miner = ? OR signing_pubkey = ?` and breaking
        ties by `ts_ok DESC` let anyone point their own attestation's
        `public_key` at another miner's identity and take over its verdict.
        So: the primary key wins outright, and the self-reported column is
        consulted only for well-formed Ed25519 keys, fail-closed on collision.

        Returns the row dict plus `_matched_field`, or None, or the marker
        {"_ambiguous": True} when one pubkey maps to several miners.
        """
        uri = f"file:{self.db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(self.COLUMNS + "WHERE miner = ?", (ident,)).fetchone()
            if row:
                out = dict(row)
                out["_matched_field"] = "miner"
                return out
            if not _ED25519_PUBKEY_HEX.match(ident or ""):
                # Not a miner-id and not shaped like a key: nothing to match.
                # Never fall through to a substring/looser match here.
                return None
            rows = conn.execute(
                self.COLUMNS + "WHERE signing_pubkey = ? ORDER BY ts_ok DESC LIMIT 2",
                (ident,),
            ).fetchall()
            if not rows:
                return None
            if len(rows) > 1:
                # Several miners claim this key. Since the claim is unverified,
                # there is no honest way to pick one — say so instead of
                # silently serving the most recent.
                return {"_ambiguous": True}
            out = dict(rows[0])
            out["_matched_field"] = "signing_pubkey"
            return out
        finally:
            conn.close()


class Signer:
    """Ed25519 oracle signer. Key persisted at key_path (0600), created if absent."""

    def __init__(self, key_path):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat)
        self._Enc, self._Pub = Encoding, PublicFormat
        if os.path.exists(key_path):
            with open(key_path) as f:
                priv_hex = json.load(f)["private_key"]
            self.priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        else:
            self.priv = Ed25519PrivateKey.generate()
            pk = self.priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            with open(key_path, "w") as f:
                json.dump({"private_key": pk.hex()}, f)
            os.chmod(key_path, 0o600)
        self.pubkey_hex = self.priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, message_bytes):
        return self.priv.sign(message_bytes).hex()


def build_verdict(ident, row, signer):
    """Build the scoped, signed attestation verdict for one identity."""
    now = int(time.time())
    if not row or row.get("_ambiguous"):
        attestation = {
            "query": ident, "found": False,
            "is_physical": None, "anti_emulation_pass": None,
            "device_family": None, "device_arch": None, "antiquity_class": None,
            "attestation_age_s": None, "fresh": False,
            "matched_field": None, "matched_miner": None,
            "ambiguous_identity": bool(row and row.get("_ambiguous")),
        }
    else:
        fp_pass = bool(row.get("fingerprint_passed"))
        age = now - int(row["ts_ok"])
        attestation = {
            "query": ident,
            "found": True,
            "is_physical": fp_pass,            # fingerprint+anti-emulation passed
            "anti_emulation_pass": fp_pass,
            "device_family": row.get("device_family"),
            "device_arch": row.get("device_arch"),
            "antiquity_class": _antiquity_class(row.get("device_arch")),
            "attestation_age_s": age,
            "fresh": age < ATTESTATION_TTL,
            # Which namespace answered, and whose row it was. `signing_pubkey`
            # is self-reported by the attesting miner; `miner` is the node's
            # primary key. A consumer pinning an identity can now tell.
            "matched_field": row.get("_matched_field"),
            "matched_miner": row.get("miner"),
            "ambiguous_identity": False,
        }
    # The signed envelope. NOTE: no field named bare `verified`.
    envelope = {
        "oracle_version": "0.1.0-single-node",
        "scope": SCOPE,
        "attestation": attestation,
        "issued_at": now,
    }
    message = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    envelope["oracle_pubkey"] = signer.pubkey_hex
    envelope["oracle_signature"] = signer.sign(message)
    envelope["verify_hint"] = "Ed25519 verify oracle_signature over compact key-sorted JSON of {oracle_version,scope,attestation,issued_at}"
    return envelope


class Handler(BaseHTTPRequestHandler):
    db = None
    signer = None

    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self._send(200, {"status": "ok", "oracle": "poa-attest",
                                    "pubkey": self.signer.pubkey_hex})
        if path.startswith("/oracle/attest/"):
            ident = path[len("/oracle/attest/"):].strip("/")
            if not ident:
                return self._send(400, {"error": "missing identity"})
            try:
                row = self.db.lookup(ident)
            except Exception as e:
                return self._send(503, {"error": f"data source unavailable: {e}"})
            return self._send(200, build_verdict(ident, row, self.signer))
        return self._send(404, {"error": "not found",
                                "endpoints": ["/oracle/attest/<id>", "/health"]})

    def log_message(self, *a):  # quiet
        pass


def main():
    p = argparse.ArgumentParser(description="PoA-Attest read-only oracle sidecar")
    p.add_argument("--db", default="/root/rustchain/rustchain_v2.db",
                   help="path to rustchain_v2.db (opened read-only)")
    p.add_argument("--key", default=os.path.expanduser("~/.poa-oracle-key.json"),
                   help="oracle Ed25519 key file (created if absent)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8097)
    args = p.parse_args()

    Handler.db = OracleDB(args.db)
    Handler.signer = Signer(args.key)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"PoA-Attest oracle on http://{args.host}:{args.port}  "
          f"pubkey={Handler.signer.pubkey_hex[:16]}...  db={args.db} (ro)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
