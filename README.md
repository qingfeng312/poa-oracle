# PoA-Attest Oracle

**Rent out the authenticity moat.** A read-only sidecar that re-exposes
RustChain's RIP-PoA hardware-authenticity verdict under an explicit scope
contract, so *external* agents and DePIN systems can ask one question:

> *"Is this peer real silicon, or a VM/emulation farm?"*

```bash
curl https://rustchain.org/oracle/attest/g4-powerbook-115
```
```json
{
  "oracle_version": "0.1.0-single-node",
  "scope": "attests: hardware is physically present and non-emulated, plus its self-reported architecture class. does NOT attest: work quality, output authenticity, operator intent, or that any specific computation occurred.",
  "attestation": {
    "query": "g4-powerbook-115", "found": true,
    "is_physical": true, "anti_emulation_pass": true,
    "device_family": "PowerPC", "device_arch": "g4",
    "antiquity_class": "vintage-ppc",
    "attestation_age_s": 100, "fresh": true
  },
  "issued_at": 1766772000,
  "oracle_pubkey": "…", "oracle_signature": "…"
}
```

## The scope contract (why this is honest)
The single rule that keeps the moat credible: **physical hardware is never the
same as legitimate work.** A real G4 running a scam still passes RIP-PoA. So the
verdict attests *only* physical-presence + non-emulation + arch-class, every
response carries the `scope` disclaimer, and **no field is ever a bare
`verified`** — the signed object is `attestation`. Consumers verify
`oracle_signature` (Ed25519) over the compact key-sorted JSON of
`{oracle_version, scope, attestation, issued_at}`.

## Architecture: zero-blast-radius sidecar
The oracle reads the node's `miner_attest_recent` table **read-only** and
re-publishes the verdict. It does **not** run inside, write to, or modify the
consensus node. Run it next to the node:

```bash
pip install poa-oracle cryptography
poa-oracle --db /root/rustchain/rustchain_v2.db --port 8076
# nginx: proxy /oracle/ -> 127.0.0.1:8076
# (or from a checkout: python3 oracle.py --db ... --port 8076)
```

## Honest status
- **Single-node signed** (v0.1). The verdict is signed by *this* oracle's key.
- Multi-node **N-of-5 co-signing is future work** and is NOT claimed here — when
  shipped it raises the trust from "one oracle says so" to "the network says so."

## MCP tool
`mcp_tool.py` provides `rustchain_verify_hardware(identity)` for rustchain-mcp —
the tool docstring repeats the scope so a calling LLM can't mistake authenticity
for work-legitimacy.

## Tests
```bash
python3 test_oracle.py   # 18 contract checks: scope present, no bare 'verified', sigs verify
```

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the
offline test workflow, and the **non-negotiable scope-contract rules** any
change must preserve (no bare `verified` field, no unioned identity
namespaces, no multi-node co-signing claims, read-only against the node).

Part of the [RustChain](https://rustchain.org) ecosystem · MIT © Elyan Labs.
