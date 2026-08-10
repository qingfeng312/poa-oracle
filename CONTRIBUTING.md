# Contributing to poa-oracle

`poa-oracle` (PoA-Attest) is a read-only sidecar that re-exposes
RustChain's hardware-authenticity verdict under an explicit scope contract.
The scope contract and the honest-labeling rules are non-negotiable — see
below.

## Development setup

The oracle depends on the standard library plus `cryptography` (for the
Ed25519 signer). From a checkout:

```bash
git clone https://github.com/Scottcjn/poa-oracle.git
cd poa-oracle
python3 -m venv .venv && . .venv/bin/activate
pip install cryptography
```

## Running the tests

`test_oracle.py` builds a temp SQLite database, exercises `OracleDB.lookup`,
`build_verdict`, and signature verification, and is fully offline:

```bash
python3 test_oracle.py
```

The oracle can also be run against a dummy database for a dry start:

```bash
python3 oracle.py --db /tmp/empty.db --host 127.0.0.1 --port 8097
curl http://127.0.0.1:8097/health
```

## The scope contract (non-negotiable)

The verdict attests ONLY that hardware is physically present, non-emulated,
and its self-reported architecture class. It does NOT attest work quality,
output authenticity, operator intent, or that any specific computation
happened. A real G4 running a scam still passes.

Changes that violate this will not be merged:

1. **No bare `verified` field.** The signed field is `attestation`; never
   add a top-level boolean that a consumer might trust without reading the
   scope.
2. **No unioning identity namespaces.** `miner` (the node's primary key)
   and `signing_pubkey` (self-reported) are resolved separately and the
   verdict reports which one answered. `OracleDB.lookup` must stay fail-closed
   on collision (`_ambiguous`), not pick the most recent.
3. **No claims about multi-node co-signing.** This is a single-node signed
   oracle. N-of-5 co-signing is documented as future work and must not be
   claimed in code or docs.
4. **Read-only against the node.** The sidecar must never write to, modify,
   or run inside the consensus node — zero blast radius on consensus.

## What makes a good contribution

- New attestation fields are fine *if* they stay within the scope (hardware
  presence, non-emulation, arch class) and are added to the signed envelope.
- A new antiquity-class label belongs in the `_ANTIQUITY` map and is a
  label, not a uniqueness claim.
- Documentation improvements — docstrings, README clarity, `docs/API.md`
  accuracy — are always welcome.

## Pull requests

- One logical change per PR; docs-only PRs should not also change behavior.
- Match the existing style (no auto-formatter reflow unless the whole file
  is touched).
- Make sure `python3 test_oracle.py` passes before requesting review.