# SPDX-License-Identifier: MIT
"""Contract tests for the PoA-Attest oracle.

The integrity of this attractor IS the scope contract: a verdict must always
carry the scope disclaimer, must never overclaim via a bare `verified` field,
and its signature must verify. These tests guard exactly that.
"""
import json
import os
import sqlite3
import tempfile

import oracle

# Ed25519 keys are 32 bytes of lowercase hex as the node stores them.
PUBKEY_G4 = "a1" * 32
PUBKEY_VM = "d4" * 32
PUBKEY_CONTESTED = "c0" * 32


def _temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE miner_attest_recent (miner TEXT PRIMARY KEY, ts_ok INTEGER, "
        "device_family TEXT, device_arch TEXT, entropy_score REAL, "
        "fingerprint_passed INTEGER, source_ip TEXT, signing_pubkey TEXT)")
    import time
    now = int(time.time())
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("g4-powerbook-115", now - 100, "PowerPC", "g4",
                  0.9, 1, None, PUBKEY_G4))
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("vm-faker", now - 50, "x86_64", "modern",
                  0.0, 0, None, PUBKEY_VM))
    # Hostile rows. `signing_pubkey` is whatever the attesting miner put in the
    # request body's `public_key` field — the node only verifies it when a
    # signature is supplied, and the unsigned path is supported. So a miner can
    # name it after somebody else and, before the namespace split, take over
    # that identity's verdict by attesting more recently.
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("attacker-vm-1", now - 5, "QEMU Virtual CPU", "x86_64",
                  0.0, 0, None, "g4-powerbook-115"))     # downgrade attempt
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("attacker-real-g4", now - 5, "PowerPC G4", "g4",
                  0.9, 1, None, "vm-farm-node-7"))       # laundering attempt
    # Two miners claiming the same well-formed key: unverifiable either way.
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("honest-g5", now - 400, "PowerPC G5", "g5",
                  0.9, 1, None, PUBKEY_CONTESTED))
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("copycat-vm", now - 5, "QEMU Virtual CPU", "x86_64",
                  0.0, 0, None, PUBKEY_CONTESTED))
    conn.commit(); conn.close()
    return path


def _signer():
    fd, kp = tempfile.mkstemp(suffix=".json"); os.close(fd); os.remove(kp)
    return oracle.Signer(kp)


def _verify_sig(env):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    inner = {k: env[k] for k in ("oracle_version", "scope", "attestation", "issued_at")}
    msg = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(env["oracle_pubkey"]))
    pk.verify(bytes.fromhex(env["oracle_signature"]), msg)  # raises on failure
    return True


fails = 0
def check(cond, label):
    global fails
    if cond: print(f"  PASS: {label}")
    else: fails += 1; print(f"  FAIL: {label}")


def main():
    db = oracle.OracleDB(_temp_db())
    signer = _signer()

    # 1. real vintage hardware -> physical=True, vintage class
    v = oracle.build_verdict("g4-powerbook-115", db.lookup("g4-powerbook-115"), signer)
    check(v["attestation"]["is_physical"] is True, "real G4 -> is_physical True")
    check(v["attestation"]["antiquity_class"] == "vintage-ppc", "g4 -> vintage-ppc class")

    # 2. VM/failed-fingerprint -> physical=False
    v2 = oracle.build_verdict("vm-faker", db.lookup("vm-faker"), signer)
    check(v2["attestation"]["is_physical"] is False, "failed-fp -> is_physical False")
    check(v2["attestation"]["anti_emulation_pass"] is False, "failed-fp -> anti_emu False")

    # 3. unknown id -> found False, still scoped + signed
    v3 = oracle.build_verdict("nobody", db.lookup("nobody"), signer)
    check(v3["attestation"]["found"] is False, "unknown id -> found False")

    # 4. THE SCOPE CONTRACT — every verdict carries it
    for tag, ver in (("real", v), ("vm", v2), ("unknown", v3)):
        check("scope" in ver and "does NOT attest" in ver["scope"], f"{tag}: scope present")
        # never a bare `verified` key anywhere in the envelope
        blob = json.dumps(ver)
        check('"verified"' not in blob, f"{tag}: no bare 'verified' field")
        check(ver["oracle_signature"] and ver["oracle_pubkey"], f"{tag}: signed")
        check(_verify_sig(ver), f"{tag}: signature verifies")

    # 5. lookup by signing_pubkey works too
    vp = oracle.build_verdict(PUBKEY_G4, db.lookup(PUBKEY_G4), signer)
    check(vp["attestation"]["found"] is True, "lookup by signing_pubkey works")
    check(vp["attestation"]["matched_field"] == "signing_pubkey",
          "pubkey lookup reports matched_field=signing_pubkey")
    check(vp["attestation"]["matched_miner"] == "g4-powerbook-115",
          "pubkey lookup reports whose row answered")

    # 6. IDENTITY NAMESPACES — the node's primary key is not the same thing as
    #    a self-reported public_key, and one must never answer for the other.
    check(v["attestation"]["matched_field"] == "miner",
          "miner-id lookup reports matched_field=miner")

    #    a) Downgrade: attacker-vm-1 attested with public_key="g4-powerbook-115"
    #       5s ago; the real G4 attested 100s ago. The PK must still win.
    vd = oracle.build_verdict("g4-powerbook-115", db.lookup("g4-powerbook-115"), signer)
    check(vd["attestation"]["matched_miner"] == "g4-powerbook-115",
          "a fresher self-reported pubkey cannot hijack a miner-id")
    check(vd["attestation"]["is_physical"] is True,
          "victim's genuine hardware keeps its verdict")
    check(vd["attestation"]["device_family"] == "PowerPC",
          "victim's device is not replaced by the attacker's")

    #    b) Laundering: nothing is named 'vm-farm-node-7'; only an attacker row
    #       claims it as its public_key. An unattested identity gets nothing.
    vl = oracle.build_verdict("vm-farm-node-7", db.lookup("vm-farm-node-7"), signer)
    check(vl["attestation"]["found"] is False,
          "non-key identity is never resolved through signing_pubkey")
    check(vl["attestation"]["is_physical"] is None,
          "laundered identity gets no physicality claim")

    #    c) Contested key: two miners claim it, so there is no honest answer.
    vc = oracle.build_verdict(PUBKEY_CONTESTED, db.lookup(PUBKEY_CONTESTED), signer)
    check(vc["attestation"]["found"] is False, "contested pubkey -> found False")
    check(vc["attestation"]["ambiguous_identity"] is True,
          "contested pubkey is reported as ambiguous, not silently resolved")
    check(vc["attestation"]["is_physical"] is None, "contested pubkey -> no verdict")

    for tag, ver in (("downgrade", vd), ("launder", vl), ("contested", vc)):
        check(_verify_sig(ver), f"{tag}: signature verifies")
        check('"verified"' not in json.dumps(ver), f"{tag}: no bare 'verified' field")

    print(f"\n{'ALL PASS' if fails==0 else str(fails)+' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
